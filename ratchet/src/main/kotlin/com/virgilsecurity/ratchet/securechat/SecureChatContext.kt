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

package com.virgilsecurity.ratchet.securechat

import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * Create new instance.
 *
 * @param identity user's identity
 * @param identityCard user's identity card id
 * @param identityKeyPair user's identity key pair (corresponding to public key in identityCard)
 * @param accessTokenProvider access token provider
 */
class SecureChatContext(
        val identity: String,
        val identityCard: Card,
        val identityKeyPair: VirgilKeyPair,
        val accessTokenProvider: AccessTokenProvider,
        val rootPath: String? = null
) {

    /**
     * Time that one-time key lives in the storage after been marked as orphaned. Seconds
     */
    var orphanedOneTimeKeyTtl = 24 * 60 * 60

    /**
     * Time that long-term key is been used before rotation. Seconds
     */
    var longTermKeyTtl = 5 * 24 * 60 * 60

    /**
     * Time that long-term key lives in the storage after been marked as outdated. Seconds
     */
    var outdatedLongTermKeyTtl = 24 * 60 * 60

    /**
     * Desired number of one-time keys
     */
    var desiredNumberOfOneTimeKeys = 100

    /**
     * App name
     */
    var appName: String? = null
}