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

package com.virgilsecurity.android.ratchet

import com.virgilsecurity.crypto.ratchet.RatchetException
import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.ratchet.exception.SecureGroupSessionException
import com.virgilsecurity.ratchet.keystorage.FileLongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.FileOneTimeKeysStorage
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureGroupSession
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.ratchet.utils.LogHelper
import com.virgilsecurity.ratchet.utils.hexEncodedString
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
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.concurrent.TimeUnit

class GroupIntegrationTest {

    private lateinit var crypto: VirgilCrypto
    private lateinit var cards: MutableList<Card>
    private lateinit var chats: MutableList<SecureChat>

    @Before
    fun setup() {
        LogHelper.instance().logLevel = TestConfig.logLevel
        this.crypto = VirgilCrypto()
    }

    private fun init(numberOfParticipants: Int) {
        val cardVerifier = VirgilCardVerifier(VirgilCardCrypto(this.crypto), true, false)
        val client = RatchetClient(URL(TestConfig.serviceURL))

        this.cards = mutableListOf()
        this.chats = mutableListOf()

        for (i in 0 until numberOfParticipants) {
            val identity = generateIdentity()
            val keyPair = this.crypto.generateKeyPair(KeyType.ED25519)
            val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
                val generator = JwtGenerator(
                        TestConfig.appId,
                        TestConfig.apiPrivateKey,
                        TestConfig.apiPublicKeyId,
                        TimeSpan.fromTime(10050, TimeUnit.MILLISECONDS), VirgilAccessTokenSigner(this.crypto)
                )

                return@RenewJwtCallback generator.generateToken(identity)
            })
            val cardManager = CardManager(
                    VirgilCardCrypto(this.crypto),
                    tokenProvider,
                    cardVerifier,
                    VirgilCardClient(TestConfig.cardsServiceURL)
            )
            val card = cardManager.publishCard(keyPair.privateKey, keyPair.publicKey)

            val longTermKeysStorage =
                    FileLongTermKeysStorage(identity, this.crypto, keyPair, TestConfig.context.filesDir.absolutePath)
            val oneTimeKeysStorage = FileOneTimeKeysStorage(identity, this.crypto, keyPair)

            val keysRotator = KeysRotator(
                    this.crypto, keyPair.privateKey, card.identifier,
                    5, 10, 5, IntegrationTest.DESIRED_NUMBER_OF_KEYS,
                    longTermKeysStorage, oneTimeKeysStorage, client
            )

            val secureChat = SecureChat(
                    this.crypto,
                    keyPair.privateKey,
                    card,
                    tokenProvider,
                    client,
                    longTermKeysStorage,
                    oneTimeKeysStorage,
                    FileSessionStorage(identity, this.crypto, keyPair, TestConfig.context.filesDir.absolutePath),
                    FileGroupSessionStorage(identity, this.crypto, keyPair, TestConfig.context.filesDir.absolutePath),
                    keysRotator
            )

            this.cards.add(card)
            this.chats.add(secureChat)
        }
    }

    @Test
    fun encrypt_decrypt__random_uuid_messages__should_decrypt() {
        val num = 10

        init(num)
        val cards1 = this.cards
        val chats1 = this.chats

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = chats1.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localCards = cards1.toMutableList()
            localCards.removeAt(i)

            val session = chats1[i].startGroupSession(localCards, initMsg)
            sessions.add(session)
        }

        Utils.encryptDecrypt100Times(sessions)

        init(num)
        val cards2 = this.cards
        val chats2 = this.chats

        val ticket1 = sessions[0].createChangeParticipantsTicket()

        for (i in 0 until num * 2) {
            if (i < num) {
                sessions[i].updateParticipants(ticket1, cards2, listOf())
            } else {
                val localCards = cards2.toMutableList()
                localCards.removeAt(i - num)

                val session = chats2[i - num].startGroupSession(cards1 + localCards, ticket1)

                sessions.add(session)
            }
        }

        Utils.encryptDecrypt100Times(sessions)

        init(num)
        val cards3 = this.cards
        val chats3 = this.chats

        val ticket2 = sessions[num].createChangeParticipantsTicket()
        sessions = sessions.subList(num, sessions.size)

        for (i in 0 until num * 2) {
            if (i < num) {
                sessions[i].updateParticipants(ticket2, cards3, cards1.map { it.identifier })
            } else {
                val localCards = cards3.toMutableList()
                localCards.removeAt(i - num)

                val session = chats3[i - num].startGroupSession(cards2 + localCards, ticket2)

                sessions.add(session)
            }
        }

        Utils.encryptDecrypt100Times(sessions)
    }

    @Test
    fun decrypt__old_session_messages__should_not_crash() {
        val num = 3
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localCards = cards.toMutableList()
            localCards.removeAt(i)

            val session = chats[i].startGroupSession(localCards, initMsg)
            sessions.add(session)
        }

        // Encrypt plaintext
        val plainText = generateText()
        val message = sessions.first().encrypt(plainText)
        val decryptedMessage1 = sessions.last().decryptString(message, cards[0].identifier)
        assertEquals(plainText, decryptedMessage1)

        // Remove user
        val experimentalCard = cards.last()
        val removeCardIds = listOf(experimentalCard.identifier)

        val removeTicket = sessions.first().createChangeParticipantsTicket()
        sessions.removeAt(sessions.size - 1)

        sessions.forEach { session ->
            session.updateParticipants(removeTicket, listOf(), removeCardIds)
        }

        // Return user
        val addTicket = sessions.first().createChangeParticipantsTicket()

        sessions.forEach { session ->
            session.updateParticipants(addTicket, listOf(experimentalCard), listOf())
        }

        val newSession = chats.last().startGroupSession(cards.dropLast(1), addTicket)
        sessions.add(newSession)

        // Decrypt with new session message, encrypted for old session
        try {
            sessions.last().decryptString(message, cards[0].identifier)
        } catch (e: RatchetException) {
            assertEquals(RatchetException.ERROR_EPOCH_NOT_FOUND, e.statusCode)
        }
    }

    @Test
    fun add_remove__user_100_times__should_not_crash() {
        val num = 3
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localCards = cards.toMutableList()
            localCards.removeAt(i)

            val session = chats[i].startGroupSession(localCards, initMsg)
            sessions.add(session)
        }

        for (i in 1 until 100) {
            // Remove user
            val experimentalCard = cards.last()
            val removeCardIds = listOf(experimentalCard.identifier)

            val removeTicket = sessions.first().createChangeParticipantsTicket()

            sessions.removeAt(sessions.size - 1)

            sessions.forEach { session ->
                session.updateParticipants(removeTicket, listOf(), removeCardIds)
            }

            // Return user
            val addTicket = sessions.first().createChangeParticipantsTicket()

            sessions.forEach { session ->
                session.updateParticipants(addTicket, listOf(experimentalCard), listOf())
            }

            val newSession = this.chats.last().startGroupSession(cards.dropLast(1), addTicket)
            sessions.add(newSession)
        }
    }

    @Test
    fun decrypt__wrong_sender__should_return_error() {
        val num = 2
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localCards = cards.toMutableList()
            localCards.removeAt(i)

            val session = chats[i].startGroupSession(localCards, initMsg)
            sessions.add(session)
        }

        val str = generateText()
        val message = sessions[0].encrypt(str)

        val decrypted = sessions[1].decryptString(message, sessions[0].myIdentifier())
        assertEquals(str, decrypted)

        val crypto = VirgilCrypto()

        try {
            sessions[1].decryptString(message, sessions[1].myIdentifier())
            fail()
        } catch (e: SecureGroupSessionException) {
            assertEquals(SecureGroupSessionException.WRONG_SENDER, e.errorCode)
        }

        try {
            val randomCardId = crypto.generateRandomData(32).hexEncodedString()
            sessions[1].decryptString(message, randomCardId)
            fail()
        } catch (e: SecureGroupSessionException) {
            assertEquals(SecureGroupSessionException.WRONG_SENDER, e.errorCode)
        }
    }

    @Test
    fun session_persistence__random_uuid_messages__should_decrypt() {
        val num = 10
        init(num)

        val sessionId = this.crypto.generateRandomData(32)
        val initMsg = this.chats.first().startNewGroupSession(sessionId)

        var sessions = mutableListOf<SecureGroupSession>()

        for (i in 0 until num) {
            val localCards = this.cards.toMutableList()
            localCards.removeAt(i)

            val session = this.chats[i].startGroupSession(localCards, initMsg)
            sessions.add(session)

            this.chats[i].storeGroupSession(session)
        }

        Utils.encryptDecrypt100TimesRestored(this.chats, sessions[0].identifier())
    }

}
