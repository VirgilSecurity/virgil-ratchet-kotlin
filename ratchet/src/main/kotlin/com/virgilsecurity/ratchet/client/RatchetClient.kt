/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.ratchet.client

import com.github.kittinunf.fuel.Fuel
import com.github.kittinunf.fuel.core.Method
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.google.gson.reflect.TypeToken
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.ratchet.build.VirgilInfo
import com.virgilsecurity.ratchet.client.data.*
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.ratchet.utils.OsUtils
import com.virgilsecurity.sdk.common.ErrorResponse
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.net.URL
import java.util.logging.Logger

/**
 *  Client used to communicate with ratchet service.
 */
class RatchetClient : RatchetClientInterface {

    private val serviceUrl: String
    private val virgilAgentHeader: String

    /**
     * Initializes a new `RatchetClient` instance.
     *
     * @param serviceUrl URL of service client will use.
     */
    @JvmOverloads
    constructor(serviceUrl: URL = URL(VIRGIL_API_BASE_URL), product: String = VIRGIL_AGENT_PRODUCT, version: String = VirgilInfo.VERSION) {
        this.serviceUrl = serviceUrl.toString()
        virgilAgentHeader =
                "$product;$VIRGIL_AGENT_FAMILY;${OsUtils.osAgentName};$version"
    }

    /**
     * Uploads public keys.
     *
     * Long-term public key signature should be verified.
     * Upload priority: identity card id > long-term public key > one-time public key.
     * Which means long-term public key can't be uploaded if identity card id is absent in the cloud and one-time
     * public key can't be uploaded if long-term public key is absent in the cloud.
     *
     * @param identityCardId Identity cardId that should be available on Card service.
     * It's public key should be ED25519.
     * @param longTermPublicKey Long-term public key + its signature created using identity private key.
     * Should be X25518 in PKCS#8.
     * @param oneTimePublicKeys One-time public keys (up to 150 keys in the cloud). Should be X25518 in PKCS#8.
     * @param token Auth token (JWT).
     *
     * @throws ProtocolException
     */
    override fun uploadPublicKeys(
            identityCardId: String?,
            longTermPublicKey: SignedPublicKey?,
            oneTimePublicKeys: List<ByteArray>,
            token: String
    ) = object : Completable {
        override fun execute() {
            val request = UploadPublicKeysRequest(identityCardId, longTermPublicKey, oneTimePublicKeys)
            executeRequest(PFS_BASE_URL, Method.PUT, request, token).get()
        }
    }

    /**
     * Checks list of keys ids and returns subset of that list with already used keys ids.
     *
     * keyId == SHA512(raw 32-byte publicKey)[0..7].
     *
     * @param longTermKeyId Long-term public key id to validate.
     * @param oneTimeKeysIds List of one-time public keys ids to validate.
     * @param token Auth token (JWT).
     *
     * @return Object with used keys ids.
     */
    override fun validatePublicKeys(
            longTermKeyId: ByteArray?,
            oneTimeKeysIds: List<ByteArray>,
            token: String
    ) = object : Result<ValidatePublicKeysResponse> {
        override fun get(): ValidatePublicKeysResponse {
            if (longTermKeyId == null && oneTimeKeysIds.isEmpty()) {
                return ValidatePublicKeysResponse(null, listOf())
            }

            val request = ValidatePublicKeysRequest(longTermKeyId, oneTimeKeysIds)
            val responseBody = executeRequest(PFS_BASE_URL + ACTIONS_VALIDATE, Method.POST, request, token).get()
            val keys = ConvertionUtils.getGson().fromJson(responseBody, ValidatePublicKeysResponse::class.java)
            return keys
        }
    }

    /**
     * Returns public keys set for given identity.
     *
     * @param identity User's identity.
     * @param token Auth token (JWT).
     *
     * @return Set of public keys.
     */
    override fun getPublicKeySet(identity: String, token: String) = object : Result<PublicKeySet> {
        override fun get(): PublicKeySet {
            val request = GetPublicKeySetRequest(identity)
            val responseBody = executeRequest(PFS_BASE_URL + ACTIONS_PICK_ONE, Method.POST, request, token).get()

            val keySet = ConvertionUtils.getGson().fromJson(responseBody, PublicKeySet::class.java)
            return keySet
        }
    }

    /**
     * Returns public keys sets for given identities.
     *
     * @param identities Users' identities.
     * @param token Auth token (JWT).
     *
     * @return Sets of public keys.
     */
    override fun getMultiplePublicKeysSets(identities: List<String>,
                                           token: String) = object : Result<List<IdentityPublicKeySet>> {
        override fun get(): List<IdentityPublicKeySet> {
            val request = GetMultiplePublicKeysSetsRequest(identities)
            val responseBody = executeRequest(PFS_BASE_URL + ACTIONS_PICK_BATCH, Method.POST, request, token).get()

            val listType = object : TypeToken<List<IdentityPublicKeySet>>() {}.type
            val keySet = ConvertionUtils.getGson().fromJson<List<IdentityPublicKeySet>>(responseBody, listType)
            return keySet
        }
    }

    /**
     * Deletes keys entity.
     *
     * @param token Auth token (JWT).
     */
    override fun deleteKeysEntity(token: String) = object : Completable {
        override fun execute() {
            executeRequest(PFS_BASE_URL, Method.DELETE, null, token).get()
        }
    }

    /**
     * Throws an [ProtocolException] if the [response] is not successful.
     */
    @Throws(ProtocolException::class)
    private fun validateResponse(response: Response) {
        if (!response.isSuccessful) {
            val errorBody = ConvertionUtils.toString(response.data)
            val error = ConvertionUtils.getGson().fromJson(errorBody, ErrorResponse::class.java)
            if (error != null) {
                throw ProtocolException(error.code, error.message)
            } else {
                throw ProtocolException()
            }
        }
    }

    /**
     * Executes request with provided [path], [method] as [Method], [body] and [token].
     *
     * @throws ProtocolException If the response is not successful.
     */
    @Throws(ProtocolException::class)
    private fun executeRequest(path: String, method: Method, body: Any?, token: String) = object : Result<String> {
        override fun get(): String {
            logger.fine("$method $path")
            val request = Fuel.request(method, "$serviceUrl$path")
                    .header(mapOf(VIRGIL_AGENT_HEADER_KEY to virgilAgentHeader))
                    .header(mapOf(VIRGIL_AUTHORIZATION_HEADER_KEY to "Virgil $token"))
            if (method == Method.POST || method == Method.PUT) {
                val jsonBody = ConvertionUtils.getGson().toJson(body)
                request.jsonBody(jsonBody)
            }
            val (_, response, result) = request.response()
            validateResponse(response)

            val responseBody = ConvertionUtils.toString(result.component1())
            logger.fine("result:\n$responseBody")

            return responseBody
        }
    }

    companion object {
        private const val VIRGIL_AGENT_HEADER_KEY = "virgil-agent"
        private const val VIRGIL_AGENT_PRODUCT = "ratchet"
        private const val VIRGIL_AGENT_FAMILY = "jvm"
        private const val VIRGIL_AUTHORIZATION_HEADER_KEY = "Authorization"

        private const val VIRGIL_API_BASE_URL = "https://api.virgilsecurity.com"
        private const val PFS_BASE_URL = "/pfs/v2/keys"
        private const val ACTIONS_VALIDATE = "/actions/validate"
        private const val ACTIONS_PICK_ONE = "/actions/pick-one"
        private const val ACTIONS_PICK_BATCH = "/actions/pick-batch"

        private val logger = Logger.getLogger(RatchetClient::class.java.name)
    }
}
