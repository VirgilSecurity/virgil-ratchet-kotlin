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

package com.virgilsecurity.ratchet

import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.ratchet.keystorage.FileLongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.FileOneTimeKeysStorage
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.ratchet.utils.logger
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.KeyType
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URL
import java.util.concurrent.TimeUnit

class IntegrationTest {

    private lateinit var crypto: VirgilCrypto
    private lateinit var senderCard: Card
    private lateinit var receiverCard: Card
    private lateinit var senderSecureChat: SecureChat
    private lateinit var receiverSecureChat: SecureChat

    @BeforeEach
    fun setup() {
        this.crypto = VirgilCrypto()

        init()
    }

    @Test
    fun encrypt_decrypt__random_uuid_messages__should_decrypt() {
        this.receiverSecureChat.rotateKeys()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)
        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)

        val decryptedMessage = receiverSession.decryptString(cipherText)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)
    }

    @Test
    fun session_persistence__random_uuid_messages__should_decrypt() {
        this.receiverSecureChat.rotateKeys()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)
        this.senderSecureChat.storeSession(senderSession)
        Assertions.assertNotNull(this.senderSecureChat.existingSession(this.receiverCard.identity))

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        this.senderSecureChat.storeSession(senderSession)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)
        Assertions.assertNotNull(this.receiverSecureChat.existingSession(this.senderCard.identity))

        val decryptedMessage = receiverSession.decryptString(cipherText)
        this.receiverSecureChat.storeSession(receiverSession)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100TimesRestored(this.senderSecureChat, this.senderCard.identity,
                this.receiverSecureChat, this.receiverCard.identity)
    }

    @Test
    fun session_removal__one_session_per_participant__should_delete_session() {
        this.receiverSecureChat.rotateKeys()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)
        Assertions.assertNull(this.senderSecureChat.existingSession(this.receiverCard.identity))

        senderSecureChat.storeSession(senderSession)
        Assertions.assertNotNull(this.senderSecureChat.existingSession(this.receiverCard.identity))

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)
        Assertions.assertNull(this.receiverSecureChat.existingSession(senderCard.identity))

        this.receiverSecureChat.storeSession(receiverSession)
        Assertions.assertNotNull(this.receiverSecureChat.existingSession(senderCard.identity))

        val decryptedMessage = receiverSession.decryptString(cipherText)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)

        this.senderSecureChat.deleteSession(receiverCard.identity)
        this.receiverSecureChat.deleteSession(senderCard.identity)

        Assertions.assertNull(this.senderSecureChat.existingSession(this.receiverCard.identity))
        Assertions.assertNull(this.receiverSecureChat.existingSession(this.senderCard.identity))
    }

    @Test
    fun reset__one_session_per_participant__should_reset() {
        this.receiverSecureChat.rotateKeys()
        this.senderSecureChat.rotateKeys()

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)
        this.senderSecureChat.storeSession(senderSession)

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        val receiverSession = this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)
        this.receiverSecureChat.storeSession(receiverSession)

        val decryptedMessage = receiverSession.decryptString(cipherText)
        Assertions.assertEquals(plainText, decryptedMessage)

        Utils.encryptDecrypt100Times(senderSession, receiverSession)

        Thread.sleep(3000)

        this.senderSecureChat.reset()
        Assertions.assertNull(this.senderSecureChat.existingSession(this.receiverCard.identity))
        Assertions.assertTrue(this.senderSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty())

        this.senderSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertTrue(this.senderSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty())
        this.senderSecureChat.oneTimeKeysStorage.stopInteraction()

        // Check that reset haven't affecter receivers
        Assertions.assertNotNull(this.receiverSecureChat.existingSession(this.senderCard.identity))

        Thread.sleep(5000)

        this.receiverSecureChat.reset()
        Assertions.assertNull(this.receiverSecureChat.existingSession(this.senderCard.identity))
        Assertions.assertTrue(this.receiverSecureChat.longTermKeysStorage.retrieveAllKeys().isEmpty())

        receiverSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertTrue(this.receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().isEmpty())
        this.receiverSecureChat.oneTimeKeysStorage.stopInteraction()
    }

    @Test
    fun start_as_receiver__one_session__should_replenish_ot_key() {
        this.receiverSecureChat.rotateKeys()
        this.senderSecureChat.rotateKeys()

        this.receiverSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, this.receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)
//        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS - 1, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)
//
//        Thread.sleep(5000)

        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        this.receiverSecureChat.oneTimeKeysStorage.stopInteraction()
    }

    @Test
    fun rotate__double_rotate_empty_storage__should_complete() {
        this.receiverSecureChat.rotateKeys()
        this.receiverSecureChat.rotateKeys()
    }

    @Test
    fun rotate__one_session__should_replenish_ot_key() {
        this.receiverSecureChat.rotateKeys()
        this.senderSecureChat.rotateKeys()

        this.receiverSecureChat.oneTimeKeysStorage.startInteraction()
        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        val senderSession = this.senderSecureChat.startNewSessionAsSender(this.receiverCard)

        val plainText = generateText()
        val cipherText = senderSession.encrypt(plainText)

        this.receiverSecureChat.rotateKeys()
        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS + 1, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        Thread.sleep(6000)

        this.receiverSecureChat.rotateKeys()
        Assertions.assertEquals(IntegrationTest.DESIRED_NUMBER_OF_KEYS, receiverSecureChat.oneTimeKeysStorage.retrieveAllKeys().size)

        this.receiverSecureChat.oneTimeKeysStorage.stopInteraction()

        try {
            this.receiverSecureChat.startNewSessionAsReceiver(this.senderCard, cipherText)
            Assertions.fail<String>()
        } catch (e: Exception) {
        }
    }

    @Test
    fun rotate__ltk_outdated__should_outdate_and_delete_ltk() {
        this.receiverSecureChat.rotateKeys()
        Assertions.assertEquals(1, receiverSecureChat.longTermKeysStorage.retrieveAllKeys().size)

        Thread.sleep(11000)

        this.receiverSecureChat.rotateKeys()
        Assertions.assertEquals(2, receiverSecureChat.longTermKeysStorage.retrieveAllKeys().size)

        Thread.sleep(5000)

        this.receiverSecureChat.rotateKeys()
        Assertions.assertEquals(1, receiverSecureChat.longTermKeysStorage.retrieveAllKeys().size)
    }

    @Test
    fun start_multiple_chats__random_uuid_messages__should_decrypt() {
        val card1 = senderCard
        val card2 = receiverCard
        val chat1 = senderSecureChat
        val chat2 = receiverSecureChat

        init()
        val card3 = senderCard
        val card4 = receiverCard
        val chat3 = senderSecureChat
        val chat4 = receiverSecureChat

        chat2.rotateKeys()
        chat3.rotateKeys()
        chat4.rotateKeys()

        val sessions = chat1.startMutipleNewSessionsAsSender(listOf(card2, card3, card4))

        val plainText2 = generateText()
        val plainText3 = generateText()
        val plainText4 = generateText()

        val cipherText2 = sessions[0].encrypt(plainText2)
        val cipherText3 = sessions[1].encrypt(plainText3)
        val cipherText4 = sessions[2].encrypt(plainText4)

        val receiverSession2 = chat2.startNewSessionAsReceiver(card1, cipherText2)
        val receiverSession3 = chat3.startNewSessionAsReceiver(card1, cipherText3)
        val receiverSession4 = chat4.startNewSessionAsReceiver(card1, cipherText4)

        val decryptedMessage2 = receiverSession2.decryptString(cipherText2)
        val decryptedMessage3 = receiverSession3.decryptString(cipherText3)
        val decryptedMessage4 = receiverSession4.decryptString(cipherText4)

        Assertions.assertEquals(plainText2, decryptedMessage2)
        Assertions.assertEquals(plainText3, decryptedMessage3)
        Assertions.assertEquals(plainText4, decryptedMessage4)

        Utils.encryptDecrypt100Times(sessions[0], receiverSession2)
        Utils.encryptDecrypt100Times(sessions[1], receiverSession3)
        Utils.encryptDecrypt100Times(sessions[2], receiverSession4)
    }

    private fun init() {
        val cardVerifier = VirgilCardVerifier(VirgilCardCrypto(this.crypto), true, false)
        val client = RatchetClient(URL(TestConfig.serviceURL))

        val senderIdentity = generateIdentity()
        val senderIdentityKeyPair = this.crypto.generateKeyPair(KeyType.ED25519)

        val senderTokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            val generator = JwtGenerator(
                    TestConfig.appId,
                    TestConfig.apiPrivateKey,
                    TestConfig.apiPublicKeyId,
                    TimeSpan.fromTime(10050, TimeUnit.MILLISECONDS),
                    VirgilAccessTokenSigner(this.crypto)
            )

            return@RenewJwtCallback generator.generateToken(senderIdentity)
        })

        val senderCardManager = CardManager(
                VirgilCardCrypto(this.crypto),
                senderTokenProvider,
                cardVerifier,
                VirgilCardClient(TestConfig.cardsServiceURL)
        )
        this.senderCard =
                senderCardManager.publishCard(senderIdentityKeyPair.privateKey, senderIdentityKeyPair.publicKey)

        val senderLongTermKeysStorage =
                FileLongTermKeysStorage(
                        senderIdentity,
                        this.crypto,
                        senderIdentityKeyPair,
                        createTempDir("testSender").absolutePath
                )
        val senderOneTimeKeysStorage = FileOneTimeKeysStorage(senderIdentity, this.crypto, senderIdentityKeyPair)
        val senderKeysRotator = KeysRotator(
                this.crypto, senderIdentityKeyPair.privateKey, this.senderCard.identifier,
                100, 100, 100, IntegrationTest.DESIRED_NUMBER_OF_KEYS,
                senderLongTermKeysStorage, senderOneTimeKeysStorage, client
        )
        this.senderSecureChat = SecureChat(
                this.crypto, senderIdentityKeyPair.privateKey, this.senderCard,
                senderTokenProvider, client, senderLongTermKeysStorage, senderOneTimeKeysStorage,
                FileSessionStorage(senderIdentity, this.crypto, senderIdentityKeyPair),
                FileGroupSessionStorage(senderIdentity, this.crypto, senderIdentityKeyPair),
                senderKeysRotator
        )

        val receiverIdentity = generateIdentity()
        val receiverIdentityKeyPair = this.crypto.generateKeyPair(KeyType.ED25519)

        val receiverTokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            val generator = JwtGenerator(
                    TestConfig.appId,
                    TestConfig.apiPrivateKey,
                    TestConfig.apiPublicKeyId,
                    TimeSpan.fromTime(10050, TimeUnit.MILLISECONDS),
                    VirgilAccessTokenSigner(this.crypto)
            )

            return@RenewJwtCallback generator.generateToken(receiverIdentity)
        })

        val receiverCardManager = CardManager(
                VirgilCardCrypto(this.crypto),
                receiverTokenProvider,
                cardVerifier,
                VirgilCardClient(TestConfig.cardsServiceURL)
        )
        this.receiverCard =
                receiverCardManager.publishCard(receiverIdentityKeyPair.privateKey, receiverIdentityKeyPair.publicKey)

        val receiverLongTermKeysStorage =
                FileLongTermKeysStorage(
                        senderIdentity,
                        this.crypto,
                        senderIdentityKeyPair,
                        createTempDir("testReceiver").absolutePath
                )
        val receiverOneTimeKeysStorage = FileOneTimeKeysStorage(receiverIdentity, this.crypto, receiverIdentityKeyPair)
        val receiverKeysRotator = KeysRotator(
                this.crypto, receiverIdentityKeyPair.privateKey, this.receiverCard.identifier,
                5, 10, 5, IntegrationTest.DESIRED_NUMBER_OF_KEYS,
                receiverLongTermKeysStorage, receiverOneTimeKeysStorage, client
        )

        this.receiverSecureChat = SecureChat(
                this.crypto, receiverIdentityKeyPair.privateKey, this.receiverCard,
                receiverTokenProvider, client, receiverLongTermKeysStorage, receiverOneTimeKeysStorage,
                FileSessionStorage(receiverIdentity, this.crypto, receiverIdentityKeyPair),
                FileGroupSessionStorage(receiverIdentity, this.crypto, receiverIdentityKeyPair),
                receiverKeysRotator
        )
    }

    companion object {
        val DESIRED_NUMBER_OF_KEYS = 5
        val LOG = logger()
    }
}
