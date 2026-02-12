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

package com.virgilsecurity.android.ratchet.sessionstorage

import com.virgilsecurity.android.ratchet.generateIdentity
import com.virgilsecurity.android.ratchet.generateText
import com.virgilsecurity.ratchet.securechat.SecureSession
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test


class SessionStorageTest {
    private lateinit var crypto: VirgilCrypto
    private lateinit var identity: String
    private lateinit var identityKeyPair: VirgilKeyPair
    private lateinit var sessionStorage: SessionStorage

    @Before
    fun setup() {
        this.crypto = VirgilCrypto()
        this.identity = generateIdentity()
        this.identityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
        this.sessionStorage = FileSessionStorage(this.identity, this.crypto, this.identityKeyPair, createTempDir("sessionStorage").absolutePath)
    }

    @Test
    fun storeSession() {
        val participantIdentity = generateIdentity()
        val receiverIdentityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
        val receiverLongTermKeyPair = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val receiverOneTimeKeyPair = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val sessionName = generateText()

        val secureSession = SecureSession(this.crypto, participantIdentity, sessionName,
                this.crypto.exportPrivateKey(this.identityKeyPair.privateKey),
                this.crypto.exportPublicKey(receiverIdentityKeyPair.publicKey),
                this.crypto.exportPublicKey(receiverLongTermKeyPair.publicKey),
                this.crypto.exportPublicKey(receiverOneTimeKeyPair.publicKey))

        this.sessionStorage.storeSession(secureSession)

        val restoredSession = this.sessionStorage.retrieveSession(participantIdentity, sessionName)
        assertNotNull(restoredSession)
        restoredSession!!
        assertEquals(participantIdentity, restoredSession.participantIdentity)
    }

    @Test
    fun deleteSession() {
        val participantIdentity = generateIdentity()
        val receiverIdentityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
        val receiverLongTermKeyPair = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val receiverOneTimeKeyPair = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val sessionName = generateText()

        val secureSession = SecureSession(this.crypto, participantIdentity, sessionName,
                this.crypto.exportPrivateKey(this.identityKeyPair.privateKey),
                this.crypto.exportPublicKey(receiverIdentityKeyPair.publicKey),
                this.crypto.exportPublicKey(receiverLongTermKeyPair.publicKey),
                this.crypto.exportPublicKey(receiverOneTimeKeyPair.publicKey))

        this.sessionStorage.storeSession(secureSession)

        assertNotNull(this.sessionStorage.retrieveSession(participantIdentity, sessionName))

        this.sessionStorage.deleteSession(participantIdentity, sessionName)
        assertNull(this.sessionStorage.retrieveSession(participantIdentity, sessionName))
    }

    @Test
    fun reset() {
        val participantIdentity = generateIdentity()
        val receiverIdentityKeyPair = this.crypto.generateKeyPair(KeyPairType.ED25519)
        val receiverLongTermKeyPair = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val receiverOneTimeKeyPair = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val sessionName = generateText()

        val secureSession = SecureSession(this.crypto, participantIdentity, sessionName,
                this.crypto.exportPrivateKey(this.identityKeyPair.privateKey),
                this.crypto.exportPublicKey(receiverIdentityKeyPair.publicKey),
                this.crypto.exportPublicKey(receiverLongTermKeyPair.publicKey),
                this.crypto.exportPublicKey(receiverOneTimeKeyPair.publicKey))

        this.sessionStorage.storeSession(secureSession)

        assertNotNull(this.sessionStorage.retrieveSession(participantIdentity, sessionName))

        this.sessionStorage.reset()
        assertNull(this.sessionStorage.retrieveSession(participantIdentity, sessionName))
    }
}
