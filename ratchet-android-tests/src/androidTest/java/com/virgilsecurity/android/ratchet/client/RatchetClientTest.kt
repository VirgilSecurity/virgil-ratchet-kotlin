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

package com.virgilsecurity.android.ratchet.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.virgilsecurity.android.ratchet.TestConfig
import com.virgilsecurity.android.ratchet.generateIdentity
import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.ratchet.client.data.SignedPublicKey
import com.virgilsecurity.ratchet.securechat.keysrotation.RatchetKeyIdCompat
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class RatchetClientTest {
    private lateinit var crypto: VirgilCrypto
    private lateinit var generator: JwtGenerator
    private lateinit var identity: String
    private lateinit var identityPrivateKey: VirgilPrivateKey
    private lateinit var card: Card
    private lateinit var client: RatchetClient

    @Before
    fun setup() {
        this.crypto = VirgilCrypto()

        init()
    }

    @After
    fun tearDown() {
    }

    @Test
    fun full_cycle__long_term_key__should_succeed() {
        val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
        val longTermKeyId = RatchetKeyIdCompat.computePublicKeyId(longTermPublicKey)
        val signature = this.crypto.generateSignature(longTermPublicKey, this.identityPrivateKey)

        val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

        val token = this.generator.generateToken(this.identity).stringRepresentation()
        this.client.uploadPublicKeys(this.card.identifier, signedLongTermKey, listOf(), token).execute()

        val response1 = this.client.validatePublicKeys(longTermKeyId, listOf(), token).get()
        if (response1.usedLongTermKeyId != null) {
            assertArrayEquals(longTermKeyId, response1.usedLongTermKeyId)
        }

        val response2 = this.client.getPublicKeySet(this.identity, token).get()
        assertArrayEquals(signedLongTermKey.publicKey, response2.longTermPublicKey.publicKey)
        assertArrayEquals(signedLongTermKey.signature, response2.longTermPublicKey.signature)
        assertNull(response2.oneTimePublicKey)
    }

    @Test
    fun full_cycle__all_keys__should_succeed() {
        val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val oneTimeKeyPair1 = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val oneTimeKey1 = this.crypto.exportPublicKey(oneTimeKeyPair1.publicKey)!!
        val oneTimeKeyPair2 = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val oneTimeKey2 = this.crypto.exportPublicKey(oneTimeKeyPair2.publicKey)!!

        val oneTimeKeyId1 = RatchetKeyIdCompat.computePublicKeyId(oneTimeKey1)
        val oneTimeKeyId2 = RatchetKeyIdCompat.computePublicKeyId(oneTimeKey2)

        val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
        val longTermKeyId = RatchetKeyIdCompat.computePublicKeyId(longTermPublicKey)
        val signature = this.crypto.generateSignature(longTermPublicKey, identityPrivateKey)

        val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

        val token = this.generator.generateToken(this.identity).stringRepresentation()

        this.client.uploadPublicKeys(card.identifier,
                                     signedLongTermKey,
                                     listOf(oneTimeKey1, oneTimeKey2), token).execute()

        val response1 = this.client.validatePublicKeys(longTermKeyId,
                                                       listOf(oneTimeKeyId1, oneTimeKeyId2),
                                                       token).get()
        if (response1.usedLongTermKeyId != null) {
            assertArrayEquals(longTermKeyId, response1.usedLongTermKeyId)
        }
        assertEquals(2, response1.usedOneTimeKeysIds.size)
        assertTrue(response1.usedOneTimeKeysIds.any { it.contentEquals(oneTimeKeyId1) })
        assertTrue(response1.usedOneTimeKeysIds.any { it.contentEquals(oneTimeKeyId2) })

        val response2 = this.client.getPublicKeySet(this.identity, token).get()
        assertArrayEquals(signedLongTermKey.publicKey, response2.longTermPublicKey.publicKey)
        assertArrayEquals(signedLongTermKey.signature, response2.longTermPublicKey.signature)
        assertNotNull(response2.oneTimePublicKey)

        val usedKeyId: ByteArray
        when {
            oneTimeKey1.contentEquals(response2.oneTimePublicKey!!) -> usedKeyId = oneTimeKeyId1
            oneTimeKey2.contentEquals(response2.oneTimePublicKey!!) -> usedKeyId = oneTimeKeyId2
            else -> {
                usedKeyId = byteArrayOf()
                fail()
            }
        }

        val response3 = this.client.validatePublicKeys(longTermKeyId,
                                                       listOf(oneTimeKeyId1, oneTimeKeyId2),
                                                       token).get()

        if (response3.usedLongTermKeyId != null) {
            assertArrayEquals(longTermKeyId, response3.usedLongTermKeyId)
        }
        assertEquals(2, response3.usedOneTimeKeysIds.size)
        assertTrue(response3.usedOneTimeKeysIds.any { it.contentEquals(oneTimeKeyId1) })
        assertTrue(response3.usedOneTimeKeysIds.any { it.contentEquals(oneTimeKeyId2) })
    }

    @Test
    fun full_cycle__multiple_identities__should_succeed() {
        class Entry(
                var identity: String,
                var token: String,
                var client: RatchetClient,
                var identityPublicKey: ByteArray,
                var longTermKey: ByteArray,
                var longTermKeySignature: ByteArray,
                var oneTimeKey1: ByteArray,
                var oneTimeKey2: ByteArray
        )

        val entries = mutableListOf<Entry>()

        for (i in 1..10) {
            val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
            val oneTimeKey1 = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)
            val oneTimeKey2 = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)

            val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
            val signature = this.crypto.generateSignature(longTermPublicKey, identityPrivateKey)

            val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

            val token = this.generator.generateToken(this.identity).stringRepresentation()

            this.client.uploadPublicKeys(
                    this.card.identifier,
                    signedLongTermKey,
                    listOf(oneTimeKey1, oneTimeKey2),
                    token
            ).execute()

            val entry = Entry(
                    this.identity,
                    token,
                    this.client,
                    this.crypto.exportPublicKey(this.crypto.extractPublicKey(identityPrivateKey)),
                    longTermPublicKey,
                    signature,
                    oneTimeKey1,
                    oneTimeKey2
            )
            entries.add(entry)

            init()
        }

        val lastEntry = entries.last()
        val response = lastEntry.client.getMultiplePublicKeysSets(entries.map { it.identity }, lastEntry.token).get()
        assertNotNull(response)
        assertEquals(entries.size, response.size)

        entries.forEach { entry ->
            val cloudEntry = response.first { it.identity == entry.identity }

            assertNotNull(cloudEntry)
            assertArrayEquals(entry.identityPublicKey, cloudEntry.identityPublicKey)
            assertArrayEquals(entry.longTermKey, cloudEntry.longTermPublicKey.publicKey)
            assertArrayEquals(entry.longTermKeySignature, cloudEntry.longTermPublicKey.signature)

            assertTrue(
                    entry.oneTimeKey1.contentEquals(cloudEntry.oneTimePublicKey!!)
                            || entry.oneTimeKey2.contentEquals(cloudEntry.oneTimePublicKey!!)
            )
        }
    }

    @Test
    fun reset__all_keys__should_succeed() {
        val longTermKey = this.crypto.generateKeyPair(KeyPairType.CURVE25519)
        val oneTimeKey = this.crypto.exportPublicKey(this.crypto.generateKeyPair(KeyPairType.CURVE25519).publicKey)

        val longTermPublicKey = this.crypto.exportPublicKey(longTermKey.publicKey)
        val signature = this.crypto.generateSignature(longTermPublicKey, identityPrivateKey)

        val signedLongTermKey = SignedPublicKey(longTermPublicKey, signature)

        val token = this.generator.generateToken(this.identity).stringRepresentation()

        this.client.uploadPublicKeys(this.card.identifier, signedLongTermKey, listOf(oneTimeKey), token).execute()

        this.client.deleteKeysEntity(token).execute()

        try {
            this.client.getPublicKeySet(this.identity, token).get()
            fail()
        } catch (e: Exception) {
        }

        this.client.uploadPublicKeys(this.card.identifier, signedLongTermKey, listOf(oneTimeKey), token).execute()

        val response = this.client.getPublicKeySet(this.identity, token).get()

        assertArrayEquals(signedLongTermKey.publicKey, response.longTermPublicKey.publicKey)
        assertArrayEquals(signedLongTermKey.signature, response.longTermPublicKey.signature)
        assertArrayEquals(oneTimeKey, response.oneTimePublicKey)
    }

    private fun init() {
        this.identity = generateIdentity()
        val identityKeyPair = crypto.generateKeyPair(KeyPairType.ED25519)
        this.identityPrivateKey = identityKeyPair.privateKey
        this.client = RatchetClient(URL(TestConfig.serviceURL))

        this.generator = JwtGenerator(
                TestConfig.appId, TestConfig.appPrivateKey, TestConfig.appPublicKeyId,
                TimeSpan.fromTime(30, TimeUnit.MINUTES), VirgilAccessTokenSigner(crypto)
        )

        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            return@RenewJwtCallback generator.generateToken(identity)
        })
        val cardCrypto = VirgilCardCrypto(crypto)
        val cardVerifier = VirgilCardVerifier(cardCrypto, true, false)
        val cardManager = CardManager(cardCrypto, tokenProvider, cardVerifier, VirgilCardClient(TestConfig.cardsServiceURL))
        this.card = cardManager.publishCard(identityKeyPair.privateKey, identityKeyPair.publicKey)
    }
}
