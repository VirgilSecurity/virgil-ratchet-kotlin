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

package com.virgilsecurity.ratchet.securechat

import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 *
 */
class SecureChatContext {

    val identityCard: Card
    val identityKeyPair: VirgilKeyPair
    val accessTokenProvider: AccessTokenProvider
    val rootPath: String?
    val virgilCrypto: VirgilCrypto
    val ratchetClient: RatchetClient

    /**
     * Create new instance.
     *
     * @param identityCard User's identity card id.
     * @param identityKeyPair User's identity key pair (corresponding to public key in identityCard).
     * @param accessTokenProvider Access token provider.
     */
    @JvmOverloads
    constructor(identityCard: Card,
                identityKeyPair: VirgilKeyPair,
                accessTokenProvider: AccessTokenProvider,
                rootPath: String? = null,
                virgilCrypto: VirgilCrypto = VirgilCrypto(),
                ratchetClient: RatchetClient = RatchetClient()) {
        this.identityCard = identityCard
        this.identityKeyPair = identityKeyPair
        this.accessTokenProvider = accessTokenProvider
        this.rootPath = rootPath
        this.virgilCrypto = virgilCrypto
        this.ratchetClient = ratchetClient
    }

    /**
     * Time that one-time key lives in the storage after been marked as orphaned in seconds.
     */
    var orphanedOneTimeKeyTtl = 24 * 60 * 60

    /**
     * Time that long-term key is been used before rotation in seconds.
     */
    var longTermKeyTtl = 5 * 24 * 60 * 60

    /**
     * Time that long-term key lives in the storage after been marked as outdated in seconds.
     */
    var outdatedLongTermKeyTtl = 24 * 60 * 60

    /**
     * Desired number of one-time keys.
     */
    var desiredNumberOfOneTimeKeys = 100
}
