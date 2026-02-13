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

import com.virgilsecurity.crypto.ratchet.RatchetMessage
import com.virgilsecurity.crypto.ratchet.RatchetSession
import com.virgilsecurity.ratchet.keystorage.LongTermKey
import com.virgilsecurity.ratchet.keystorage.OneTimeKey
import com.virgilsecurity.ratchet.securechat.keysrotation.RatchetKeyIdCompat
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import java.nio.charset.StandardCharsets

/**
 * Secure session.
 */
class SecureSession {

    /**
     * Participant identity.
     */
    val participantIdentity: String

    /**
     * Session name.
     */
    val name: String

    /**
     * Crypto.
     */
    val crypto: VirgilCrypto

    private var ratchetSession: RatchetSession

    /**
     * Create new instance as a receiver.
     *
     * @param crypto VirgilCrypto
     * @param participantIdentity Participant identity.
     * @param name Session name.
     * @param senderIdentityPublicKey Sender identity public key.
     * @param receiverIdentityPrivateKey Receiver identity private key.
     * @param receiverLongTermPrivateKey Receiver long-term private key.
     * @param receiverOneTimePrivateKey Receiver one-time private key.
     * @param ratchetMessage RatchetMessage.
     */
    constructor(
            crypto: VirgilCrypto, participantIdentity: String,
            name: String,
            senderIdentityPublicKey: VirgilPublicKey,
            receiverIdentityPrivateKey: VirgilPrivateKey,
            receiverLongTermPrivateKey: LongTermKey,
            receiverOneTimePrivateKey: OneTimeKey?,
            ratchetMessage: RatchetMessage
    ) {
        this.crypto = crypto
        this.participantIdentity = participantIdentity
        this.name = name

        this.ratchetSession = RatchetSession()
        ratchetSession.setRng(crypto.rng)

        val senderIdentityPublicKeyObj = senderIdentityPublicKey.publicKey
        val receiverIdentityPrivateKeyObj = receiverIdentityPrivateKey.privateKey
        val receiverLongTermPrivateKeyObj = this.crypto.importPrivateKey(receiverLongTermPrivateKey.key).privateKey.privateKey

        if (receiverOneTimePrivateKey == null) {
            this.ratchetSession.respondNoOneTimeKey(
                    senderIdentityPublicKeyObj,
                    receiverIdentityPrivateKeyObj,
                    receiverLongTermPrivateKeyObj,
                    ratchetMessage,
                    false
            )
        } else {
            val receiverOneTimePrivateKeyObj = this.crypto.importPrivateKey(receiverOneTimePrivateKey.key).privateKey.privateKey
            this.ratchetSession.respond(
                    senderIdentityPublicKeyObj,
                    receiverIdentityPrivateKeyObj,
                    receiverLongTermPrivateKeyObj,
                    receiverOneTimePrivateKeyObj,
                    ratchetMessage,
                    false
            )
        }
    }

    /**
     * Create new instance as a sender.
     *
     * @param crypto VirgilCrypto.
     * @param participantIdentity Participant identity.
     * @param name Session name.
     * @param senderIdentityPrivateKey Sender identity private key.
     * @param receiverIdentityPublicKey Receiver identity public key.
     * @param receiverLongTermPublicKey Receiver long-term public key.
     * @param receiverOneTimePublicKey Receiver one-time public key.
     */
    constructor(
            crypto: VirgilCrypto, participantIdentity: String,
            name: String, senderIdentityPrivateKey: ByteArray, senderIdentityKeyId: ByteArray,
            receiverIdentityPublicKey: ByteArray, receiverIdentityKeyId: ByteArray,
            receiverLongTermPublicKey: ByteArray, receiverLongTermKeyId: ByteArray,
            receiverOneTimePublicKey: ByteArray?, receiverOneTimeKeyId: ByteArray?
    ) {
        this.crypto = crypto
        this.participantIdentity = participantIdentity
        this.name = name

        this.ratchetSession = RatchetSession()
        ratchetSession.setRng(crypto.rng)

        val senderIdentityPrivateKeyObj = this.crypto.importPrivateKey(senderIdentityPrivateKey).privateKey.privateKey
        val receiverIdentityPublicKeyObj = this.crypto.importPublicKey(receiverIdentityPublicKey).publicKey
        val receiverLongTermPublicKeyObj = this.crypto.importPublicKey(receiverLongTermPublicKey).publicKey

        if (receiverOneTimePublicKey == null || receiverOneTimeKeyId == null) {
            ratchetSession.initiateNoOneTimeKey(
                    senderIdentityPrivateKeyObj,
                    senderIdentityKeyId,
                    receiverIdentityPublicKeyObj,
                    receiverIdentityKeyId,
                    receiverLongTermPublicKeyObj,
                    receiverLongTermKeyId,
                    false
            )
        } else {
            val receiverOneTimePublicKeyObj = this.crypto.importPublicKey(receiverOneTimePublicKey).publicKey
            ratchetSession.initiate(
                    senderIdentityPrivateKeyObj,
                    senderIdentityKeyId,
                    receiverIdentityPublicKeyObj,
                    receiverIdentityKeyId,
                    receiverLongTermPublicKeyObj,
                    receiverLongTermKeyId,
                    receiverOneTimePublicKeyObj,
                    receiverOneTimeKeyId,
                    false
            )
        }
    }

    /**
     * Backward-compatible sender constructor that computes key ids from provided keys.
     */
    constructor(
            crypto: VirgilCrypto,
            participantIdentity: String,
            name: String,
            senderIdentityPrivateKey: ByteArray,
            receiverIdentityPublicKey: ByteArray,
            receiverLongTermPublicKey: ByteArray,
            receiverOneTimePublicKey: ByteArray?
    ) : this(
            crypto,
            participantIdentity,
            name,
            senderIdentityPrivateKey,
            RatchetKeyIdCompat.computePublicKeyId(
                    crypto.exportPublicKey(crypto.extractPublicKey(crypto.importPrivateKey(senderIdentityPrivateKey).privateKey))
            ),
            receiverIdentityPublicKey,
            RatchetKeyIdCompat.computePublicKeyId(receiverIdentityPublicKey),
            receiverLongTermPublicKey,
            RatchetKeyIdCompat.computePublicKeyId(receiverLongTermPublicKey),
            receiverOneTimePublicKey,
            receiverOneTimePublicKey?.let { RatchetKeyIdCompat.computePublicKeyId(it) }
    )

    /**
     * Restore session from serialized representation.
     *
     * @param data Serialized session.
     * @param participantIdentity Participant identity.
     * @param name Session name.
     * @param crypto VirgilCrypto.
     */
    constructor(
            data: ByteArray, participantIdentity: String, name: String, crypto: VirgilCrypto
    ) {
        this.ratchetSession = RatchetSession.deserialize(data)
        ratchetSession.setRng(crypto.rng)
        this.participantIdentity = participantIdentity
        this.name = name
        this.crypto = crypto
    }

    /**
     * Encrypts string.
     *
     * NOTE: This operation changes session state, so session should be updated in storage.
     *
     * @param str Message to encrypt.
     * @return RatchetMessage.
     */
    fun encrypt(str: String): RatchetMessage {
        val data = str.toByteArray(StandardCharsets.UTF_8)

        return this.encrypt(data)
    }

    /**
     * Encrypts data.
     *
     * NOTE: This operation changes session state, so session should be updated in storage.
     *
     * @param data Message to encrypt.
     * @return RatchetMessage.
     */
    fun encrypt(data: ByteArray): RatchetMessage {
        synchronized(ratchetSession) {
            return ratchetSession.encrypt(data)
        }
    }

    /**
     * Decrypts data from RatchetMessage.
     *
     * NOTE: This operation changes session state, so session should be updated in storage.
     *
     * @param message RatchetMessage.
     * @return Decrypted data.
     */
    fun decryptData(message: RatchetMessage): ByteArray {
        synchronized(ratchetSession) {
            return ratchetSession.decrypt(message)
        }
    }

    /**
     * Decrypts utf-8 string from RatchetMessage.
     *
     * NOTE: This operation changes session state, so session should be updated in storage.
     *
     * @param message RatchetMessage.
     * @return Decrypted utf-8 string.
     */
    fun decryptString(message: RatchetMessage): String {
        val data = this.decryptData(message)
        return data.toString(StandardCharsets.UTF_8)
    }

    /**
     * Serialize session.
     */
    fun serialize(): ByteArray {
        return this.ratchetSession.serialize()
    }
}
