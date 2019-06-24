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

import com.virgilsecurity.ratchet.data.IdentityPublicKeySet
import com.virgilsecurity.ratchet.data.PublicKeySet
import com.virgilsecurity.ratchet.data.SignedPublicKey
import com.virgilsecurity.ratchet.data.ValidatePublicKeysResponse

/**
 *  Client used to communicate with ratchet service
 */
interface RatchetClientInterface {

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
     */
    fun uploadPublicKeys(
            identityCardId: String?,
            longTermPublicKey: SignedPublicKey?,
            oneTimePublicKeys: List<ByteArray>,
            token: String
    )

    /**
     * Checks list of keys ids and returns subset of that list with already used keys ids.
     *
     * keyId == SHA512(raw 32-byte publicKey)[0..7].
     *
     * @param longTermKeyId long-term public key id to validate.
     * @param oneTimeKeysIds list of one-time public keys ids to validate.
     * @param token auth token (JWT).
     *
     * @return Object with used keys ids.
     */
    fun validatePublicKeys(
            longTermKeyId: ByteArray?,
            oneTimeKeysIds: List<ByteArray>,
            token: String
    ): ValidatePublicKeysResponse

    /**
     * Returns public keys set for given identity.
     *
     * @param identity User's identity.
     * @param token auth token (JWT).
     *
     * @return Set of public keys.
     */
    fun getPublicKeySet(identity: String, token: String): PublicKeySet

    /**
     * Returns public keys sets for given identities.
     *
     * @param identities Users' identities
     * @param token auth token (JWT)
     *
     * @return Sets of public keys.
     */
    fun getMultiplePublicKeysSets(identities: List<String>, token: String): List<IdentityPublicKeySet>

    /**
     * Deletes keys entity.
     *
     * @param token auth token (JWT).
     */
    fun deleteKeysEntity(token: String)

}
