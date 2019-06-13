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

import com.virgilsecurity.crypto.ratchet.RatchetMessage
import com.virgilsecurity.crypto.ratchet.RatchetSession
import com.virgilsecurity.ratchet.keystorage.LongTermKey
import com.virgilsecurity.ratchet.keystorage.OneTimeKey
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import java.nio.charset.StandardCharsets

/**
 * Secure session.
 */
class SecureSession {

    val participantIdentity: String
    val name: String
    val crypto: VirgilCrypto
    val sessionStorage: SessionStorage

    private var ratchetSession: RatchetSession

    /**
     * Create new instance as a receiver.
     */
    constructor(
        crypto: VirgilCrypto, sessionStorage: SessionStorage, participantIdentity: String,
        name: String, receiverIdentityPrivateKey: VirgilPrivateKey, receiverLongTermPrivateKey: LongTermKey,
        receiverOneTimePrivateKey: OneTimeKey?,
        senderIdentityPublicKey: ByteArray, ratchetMessage: RatchetMessage
    ) {

        this.crypto = crypto
        this.sessionStorage = sessionStorage
        this.participantIdentity = participantIdentity
        this.name = name

        this.ratchetSession = RatchetSession()
        ratchetSession.setRng(crypto.rng)

        this.ratchetSession.respond(senderIdentityPublicKey,
            this.crypto.exportPrivateKey(receiverIdentityPrivateKey),
            receiverLongTermPrivateKey.key,
            receiverOneTimePrivateKey?.key ?: byteArrayOf(),
            ratchetMessage)
    }

    /**
     * Create new instance as a sender.
     */
    constructor(
        crypto: VirgilCrypto, sessionStorage: SessionStorage, participantIdentity: String,
        name: String, senderIdentityPrivateKey: ByteArray, receiverIdentityPublicKey: ByteArray,
        receiverLongTermPublicKey: ByteArray, receiverOneTimePublicKey: ByteArray?
    ) {
        this.crypto = crypto
        this.sessionStorage = sessionStorage
        this.participantIdentity = participantIdentity
        this.name = name

        this.ratchetSession = RatchetSession()
        ratchetSession.setRng(crypto.rng)

        ratchetSession.initiate(
            senderIdentityPrivateKey, receiverIdentityPublicKey, receiverLongTermPublicKey,
            receiverOneTimePublicKey
        )
    }

    /**
     * Restore session from serialized representation.
     *
     * @param data Serialized session
     * @param participantIdentity participant identity
     * @param name name
     * @param sessionStorage SessionStorage
     * @param crypto VirgilCrypto
     */
    constructor(
        data: ByteArray, participantIdentity: String, name: String,
        sessionStorage: SessionStorage, crypto: VirgilCrypto
    ) {
        this.ratchetSession = RatchetSession.deserialize(data)
        ratchetSession.setRng(crypto.rng)
        this.participantIdentity = participantIdentity
        this.name = name
        this.sessionStorage = sessionStorage
        this.crypto = crypto
    }

    /**
     * Encrypts string. Updates session in storage.
     *
     * @param str message to encrypt.
     * @return RatchetMessage
     */
    fun encrypt(str: String): RatchetMessage {
        val data = str.toByteArray(StandardCharsets.UTF_8)

        return this.encrypt(data)
    }

    /**
     * Encrypts data. Updates session in storage.
     *
     * @param data message to encrypt.
     * @return RatchetMessage
     */
    fun encrypt(data: ByteArray): RatchetMessage {
        synchronized(ratchetSession) {
            val msg = this.ratchetSession.encrypt(data)
            this.sessionStorage.storeSession(this)
            return msg
        }
    }

    /**
     * Decrypts data from RatchetMessage. Updates session in storage.
     *
     * @param message RatchetMessage
     * @return Decrypted data
     */
    fun decryptData(message: RatchetMessage): ByteArray {
        synchronized(ratchetSession) {
            val data = this.ratchetSession.decrypt(message)
            this.sessionStorage.storeSession(this)
            return data
        }
    }

    /**
     * Decrypts utf-8 string from RatchetMessage. Updates session in storage.
     *
     * @param message RatchetMessage
     * @return Decrypted utf-8 string
     */
    fun decryptString(message: RatchetMessage): String {
        val data = this.decryptData(message)
        val string = data.toString(StandardCharsets.UTF_8)
        return string
    }

    /**
     * Serialize session.
     */
    fun serialize(): ByteArray {
        return this.ratchetSession.serialize()
    }
}