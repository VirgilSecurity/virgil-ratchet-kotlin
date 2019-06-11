/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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
import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import com.virgilsecurity.ratchet.build.VersionVirgilAgent
import com.virgilsecurity.ratchet.data.*
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.ratchet.utils.OsUtils
import java.net.URL

/**
 *  Client used to communicate with ratchet service
 */
class RatchetClient : RatchetClientInterface {

    private val serviceUrl: String
    private val virgilAgentHeader: String
    private val gson: Gson = GsonBuilder().create()

    /**
     * Initializes a new `RatchetClient` instance.
     */
    constructor() {
        serviceUrl = "https://api.virgilsecurity.com"
        virgilAgentHeader =
            "$VIRGIL_AGENT_PRODUCT;$VIRGIL_AGENT_FAMILY;${OsUtils.osAgentName};${VersionVirgilAgent.VERSION}"
    }

    /**
     * Initializes a new `RatchetClient` instance.
     *
     * @param serviceUrl URL of service client will use.
     */
    constructor(serviceUrl: URL) {
        this.serviceUrl = serviceUrl.toString()
        virgilAgentHeader =
            "$VIRGIL_AGENT_PRODUCT;$VIRGIL_AGENT_FAMILY;${OsUtils.osAgentName};${VersionVirgilAgent.VERSION}"
    }

    companion object {
        private const val VIRGIL_AGENT_HEADER_KEY = "virgil-agent"
        private const val VIRGIL_AGENT_PRODUCT = "ratchet"
        private const val VIRGIL_AGENT_FAMILY = "jvm"
        private const val VIRGIL_AUTHORIZATION_HEADER_KEY = "Authorization"
    }

    /**
     * Uploads public keys.
     *
     * Long-term public key signature should be verified.
     * Upload priority: identity card id > long-term public key > one-time public key.
     * Which means long-term public key can't be uploaded if identity card id is absent in the cloud and one-time public key can't be uploaded if long-term public key is absent in the cloud.
     *
     * @param identityCardId Identity cardId that should be available on Card service. It's public key should be ED25519.
     * @param longTermPublicKey long-term public key + its signature created using identity private key. Should be X25518 in PKCS#8.
     * @param oneTimePublicKeys one-time public keys (up to 150 keys in the cloud). Should be X25518 in PKCS#8
     * @param token auth token (JWT)
     *
     * @throws ProtocolException
     */
    override fun uploadPublicKeys(
        identityCardId: String?,
        longTermPublicKey: SignedPublicKey?,
        oneTimePublicKeys: List<ByteArray>,
        token: String
    ) {
        val request = UploadPublicKeysRequest(identityCardId, longTermPublicKey, oneTimePublicKeys)
        doPost("/pfs/v2/keys", request, token)
    }

    /**
     * Checks list of keys ids and returns subset of that list with already used keys ids.
     *
     * keyId == SHA512(raw 32-byte publicKey)[0..<8].
     *
     * @param longTermKeyId long-term public key id to validate.
     * @param oneTimeKeysIds list of one-time public keys ids to validate.
     * @param token auth token (JWT).
     *
     * @return Object with used keys ids.
     */
    override fun validatePublicKeys(
        longTermKeyId: ByteArray?,
        oneTimeKeysIds: List<ByteArray>,
        token: String
    ): ValidatePublicKeysResponse {
        if (longTermKeyId == null && oneTimeKeysIds.isEmpty()) {
            return ValidatePublicKeysResponse(null, listOf())
        }

        val request = ValidatePublicKeysRequest(longTermKeyId, oneTimeKeysIds)
        val responseBody = doPost("/pfs/v2/keys/actions/validate", request, token)
        val keys = gson.fromJson(responseBody, ValidatePublicKeysResponse::class.java)
        return keys
    }

    /**
     * Returns public keys set for given identity.
     *
     * @param identity User's identity.
     * @param token auth token (JWT).
     *
     * @return Set of public keys.
     */
    override fun getPublicKeySet(identity: String, token: String): PublicKeySet {
        val request = GetPublicKeySetRequest(identity)
        val responseBody = doPost("/pfs/v2/keys/actions/pick-one", request, token)

        val keySet = gson.fromJson(responseBody, PublicKeySet::class.java)
        return keySet
    }

    /**
     * Returns public keys sets for given identities.
     *
     * @param identities Users' identities
     * @param token auth token (JWT)
     *
     * @return Sets of public keys.
     */
    override fun getMultiplePublicKeysSets(identities: List<String>, token: String): List<IdentityPublicKeySet> {
        val request = GetMultiplePublicKeysSetsRequest(identities)
        val responseBody = doPost("/pfs/v2/keys/actions/pick-batch", request, token)

        val listType = object : TypeToken<List<IdentityPublicKeySet>>() {}.type
        val keySet = gson.fromJson<List<IdentityPublicKeySet>>(responseBody, listType)
        return keySet
    }

    /**
     * Deletes keys entity.
     *
     * @param token auth token (JWT).
     */
    override fun deleteKeysEntity(token: String) {
        doDelete("pfs/v2/keys", token)
    }

    /**
     * Throws an [ProtocolException] or [ProtocolHttpException] if the [response] is not successful.
     */
    @Throws(ProtocolException::class)
    private fun validateResponse(response: Response) {
        if (!response.isSuccessful) {
            //TODO Get service error type
            throw ProtocolException()
        }
    }

    private fun doPost(path: String, body: Any, token: String): String {
        val (_, response, result) = Fuel.post("$serviceUrl$path")
            .header(mapOf(VIRGIL_AGENT_HEADER_KEY to virgilAgentHeader))
            .header(mapOf(VIRGIL_AUTHORIZATION_HEADER_KEY to "Virgil $token"))
            .jsonBody(gson.toJson(body)).response()
        validateResponse(response)

        return result.toString()
    }

    private fun doDelete(path: String, token: String): String {
        val (_, response, result) = Fuel.delete("$serviceUrl$path")
            .header(mapOf(VIRGIL_AGENT_HEADER_KEY to virgilAgentHeader))
            .header(mapOf(VIRGIL_AUTHORIZATION_HEADER_KEY to "Virgil $token"))
            .response()
        validateResponse(response)

        return result.toString()
    }
}
