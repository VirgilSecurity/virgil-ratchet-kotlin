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

package com.virgilsecurity.android.ratchet.securechat

import com.virgilsecurity.android.ratchet.FakeKeysRotator
import com.virgilsecurity.android.ratchet.InMemoryCardClient
import com.virgilsecurity.android.ratchet.InMemoryGroupSessionStorage
import com.virgilsecurity.android.ratchet.InMemoryLongTermKeysStorage
import com.virgilsecurity.android.ratchet.InMemoryOneTimeKeysStorage
import com.virgilsecurity.android.ratchet.InMemoryRatchetClient
import com.virgilsecurity.android.ratchet.InMemorySessionStorage
import com.virgilsecurity.android.ratchet.TestConfig
import com.virgilsecurity.android.ratchet.TrustAllCardVerifier
import com.virgilsecurity.android.ratchet.Utils
import com.virgilsecurity.ratchet.exception.SecureChatException
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.KeyType
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider
import org.junit.jupiter.api.*
import java.util.concurrent.TimeUnit

class SecureSessionTest {

    lateinit var senderCard: Card
    lateinit var receiverCard: Card
    lateinit var senderSecureChat: SecureChat
    lateinit var receiverSecureChat: SecureChat

    @BeforeEach
    fun setup() {
        val crypto = TestConfig.virgilCrypto
        val receiverIdentityKeyPair = crypto.generateKeyPair(KeyType.ED25519)
        val senderIdentityKeyPair = crypto.generateKeyPair(KeyType.ED25519)

        val senderIdentity = com.virgilsecurity.android.ratchet.generateIdentity()
        val receiverIdentity = com.virgilsecurity.android.ratchet.generateIdentity()

        val receiverTokenProvider = CallbackJwtProvider(
            CallbackJwtProvider.GetTokenCallback {
                val generator = JwtGenerator(
                        TestConfig.appId, TestConfig.apiPrivateKey, TestConfig.apiPublicKeyId,
                        TimeSpan.fromTime(10050, TimeUnit.SECONDS), VirgilAccessTokenSigner(crypto)
                )

                return@GetTokenCallback generator.generateToken(receiverIdentity).stringRepresentation()
            })

        val senderTokenProvider = CallbackJwtProvider(
            CallbackJwtProvider.GetTokenCallback {
                val generator = JwtGenerator(
                        TestConfig.appId, TestConfig.apiPrivateKey, TestConfig.apiPublicKeyId,
                        TimeSpan.fromTime(10050, TimeUnit.SECONDS), VirgilAccessTokenSigner(crypto)
                )

                return@GetTokenCallback generator.generateToken(senderIdentity).stringRepresentation()
            })

        var cardVerifier = TrustAllCardVerifier()
        var ramCardClient = InMemoryCardClient()

        val senderCardManager = CardManager(VirgilCardCrypto(crypto), senderTokenProvider, cardVerifier, ramCardClient)

        val receiverCardManager =
            CardManager(VirgilCardCrypto(crypto), receiverTokenProvider, cardVerifier, ramCardClient)

        this.receiverCard =
            receiverCardManager.publishCard(receiverIdentityKeyPair.privateKey, receiverIdentityKeyPair.publicKey)
        this.senderCard =
            senderCardManager.publishCard(senderIdentityKeyPair.privateKey, senderIdentityKeyPair.publicKey)

        val receiverLongTermKeysStorage = InMemoryLongTermKeysStorage()
        val receiverOneTimeKeysStorage = InMemoryOneTimeKeysStorage()

        val fakeClient = InMemoryRatchetClient(receiverCardManager)

        this.senderSecureChat = SecureChat(
                crypto, senderIdentityKeyPair.privateKey, senderCard,
                senderTokenProvider, fakeClient, InMemoryLongTermKeysStorage(),
                InMemoryOneTimeKeysStorage(), InMemorySessionStorage(), InMemoryGroupSessionStorage(),
                FakeKeysRotator()
        )

        val receiverKeysRotator = KeysRotator(
            crypto, receiverIdentityKeyPair.privateKey, receiverCard.identifier, 100,
            100, 100, 10, receiverLongTermKeysStorage,
            receiverOneTimeKeysStorage, fakeClient
        )

        this.receiverSecureChat = SecureChat(
                crypto, receiverIdentityKeyPair.privateKey,
                receiverCard, receiverTokenProvider, fakeClient, receiverLongTermKeysStorage,
                receiverOneTimeKeysStorage, InMemorySessionStorage(),
                InMemoryGroupSessionStorage(), receiverKeysRotator
        )
    }

    @Test
    fun encrypt_decrypt__random_uuid_messages_ram_client__should_decrypt() {
        this.receiverSecureChat.rotateKeys()
        val senderSession = this.senderSecureChat.startNewSessionAsSender(receiverCard)

        val plainText = com.virgilsecurity.android.ratchet.generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(senderCard, cipherText)
        val decryptedMessage = receiverSession.decryptString(cipherText)

        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)
    }

    @Test
    fun session_persistence__random_uuid_messages_ram_client__should_decrypt() {
        this.receiverSecureChat.rotateKeys()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)
        this.senderSecureChat.storeSession(senderSession)

        Assertions.assertNotNull(this.senderSecureChat.existingSession(this.receiverCard.identity))

        val plainText = com.virgilsecurity.android.ratchet.generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)

        Assertions.assertNotNull(this.receiverSecureChat.existingSession(this.senderCard.identity))

        val decryptedMessage = receiverSession.decryptString(cipherText)

        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100TimesRestored(
            this.senderSecureChat,
            this.senderCard.identity,
            this.receiverSecureChat,
            this.receiverCard.identity
        )
    }

    @Test
    fun session_persistence__recreate_session__should_throw_error() {
        this.receiverSecureChat.rotateKeys()
        val senderSession = senderSecureChat.startNewSessionAsSender(receiverCard)
        this.senderSecureChat.storeSession(senderSession)

        val plainText = com.virgilsecurity.android.ratchet.generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(senderCard, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)

        try {
            this.senderSecureChat.startNewSessionAsSender(receiverCard)
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }

        try {
            this.senderSecureChat.startNewSessionAsReceiver(receiverCard, cipherText)
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }

        try {
            this.receiverSecureChat.startNewSessionAsSender(senderCard)
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }
        try {
            this.receiverSecureChat.startNewSessionAsReceiver(senderCard, cipherText)
            Assertions.fail<String>()
        } catch (e: SecureChatException) {
            Assertions.assertEquals(SecureChatException.SESSION_ALREADY_EXISTS, e.errorCode)
        } catch (e: Exception) {
            Assertions.fail<String>()
        }
    }
}