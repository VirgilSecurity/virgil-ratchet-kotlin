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

package com.virgilsecurity.ratchet.client.data

import com.google.gson.annotations.SerializedName

/**
 * Request for uploading public keys. Where [identityCardId] is *Card* id, [longTermPublicKey] is long term
 * public key and [oneTimePublicKeys] is one time public keys.
 */
class UploadPublicKeysRequest(
        @SerializedName("identity_card_id") val identityCardId: String?,
        @SerializedName("long_term_key") val longTermPublicKey: SignedPublicKey?,
        @SerializedName("one_time_keys") val oneTimePublicKeys: List<ByteArray>
)

/**
 * Response for public key validation. Where [usedLongTermKeyId] is the long-term public key id,
 * [usedOneTimeKeysIds] is one-time keys ids.
 */
class ValidatePublicKeysRequest(
        @SerializedName("long_term_key_id") val usedLongTermKeyId: ByteArray? = null,
        @SerializedName("one_time_keys_ids") val usedOneTimeKeysIds: List<ByteArray>
)

/**
 * Response for public key validation. Where [usedLongTermKeyId] is the long-term public key id,
 * [usedOneTimeKeysIds] is one-time keys ids.
 */
class ValidatePublicKeysResponse(
        @SerializedName("used_long_term_key_id") val usedLongTermKeyId: ByteArray? = null,
        @SerializedName("used_one_time_keys_ids") val usedOneTimeKeysIds: List<ByteArray>
)

/**
 * Request to get public keys set. Where [identity] is the identity by which keys set should be taken.
 */
class GetPublicKeySetRequest(@SerializedName("identity") val identity: String)

/**
 * Request to get multiple public keys sets. Where [identities] are identities by which multiple
 * keys sets should be taken.
 */
class GetMultiplePublicKeysSetsRequest(@SerializedName("identities") val identities: List<String>)
