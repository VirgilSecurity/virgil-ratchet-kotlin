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

package com.virgilsecurity.ratchet.securechat.keysrotation

import com.virgilsecurity.crypto.ratchet.RatchetKeyId
import com.virgilsecurity.ratchet.*
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.TokenContext
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

class KeysRotatorTest {

    private lateinit var keyId: RatchetKeyId
    private lateinit var crypto: VirgilCrypto
    private lateinit var cardManager: CardManager
    private lateinit var tokenProvider: AccessTokenProvider
    private lateinit var generator: JwtGenerator
    private lateinit var identity: String
    private lateinit var privateKey: VirgilPrivateKey
    private lateinit var card: Card

    @BeforeEach
    fun setup() {
        this.keyId = RatchetKeyId()
        this.crypto = VirgilCrypto()

        val identityKeyPair = this.crypto.generateKeyPair(KeyType.ED25519)
        this.identity = generateIdentity()
        this.privateKey = TestConfig.apiPrivateKey
        this.generator = JwtGenerator(
                TestConfig.appId,
                this.privateKey,
                TestConfig.apiPublicKeyId,
                TimeSpan.fromTime(10050, TimeUnit.MILLISECONDS),
                VirgilAccessTokenSigner(this.crypto)
        )

        this.tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            return@RenewJwtCallback generator.generateToken(identity)
        })
        val cardVerifier = VirgilCardVerifier(VirgilCardCrypto(crypto), true, false)

        this.cardManager = CardManager(
                VirgilCardCrypto(this.crypto),
                this.tokenProvider,
                cardVerifier,
                VirgilCardClient(TestConfig.cardsServiceURL)
        )

        this.card = this.cardManager.publishCard(identityKeyPair.privateKey, identityKeyPair.publicKey)
    }

    @Test
    fun rotate__empty_storage__should_create_keys() {
        val numberOfOneTimeKeys = 5

        val fakeLongTermKeysStorage = InMemoryLongTermKeysStorage()
        val fakeOneTimeKeysStorage = InMemoryOneTimeKeysStorage()
        val fakeClient = InMemoryRatchetClient(this.cardManager)

        val rotator = KeysRotator(
                this.crypto, this.privateKey, this.card.identifier,
                100, 100, 100, numberOfOneTimeKeys,
                fakeLongTermKeysStorage, fakeOneTimeKeysStorage, fakeClient
        )

        val log = rotate(rotator, this.tokenProvider)

        Assertions.assertEquals(1, log.longTermKeysRelevant)
        Assertions.assertEquals(1, log.longTermKeysAdded)
        Assertions.assertEquals(0, log.longTermKeysDeleted)
        Assertions.assertEquals(0, log.longTermKeysMarkedOutdated)
        Assertions.assertEquals(0, log.longTermKeysOutdated)
        Assertions.assertEquals(numberOfOneTimeKeys, log.oneTimeKeysRelevant)
        Assertions.assertEquals(numberOfOneTimeKeys, log.oneTimeKeysAdded)
        Assertions.assertEquals(0, log.oneTimeKeysDeleted)
        Assertions.assertEquals(0, log.oneTimeKeysMarkedOrphaned)
        Assertions.assertEquals(0, log.oneTimeKeysOrphaned)
        Assertions.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assertions.assertEquals(1, fakeLongTermKeysStorage.map.size)
        Assertions.assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        Assertions.assertEquals(this.identity, user.key)
        Assertions.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
    }

    @Test
    fun rotate__old_long_term_key__should_recreate_key() {
        val numberOfOneTimeKeys = 5
        val fakeLongTermKeysStorage = InMemoryLongTermKeysStorage()
        val fakeOneTimeKeysStorage = InMemoryOneTimeKeysStorage()
        val fakeClient = InMemoryRatchetClient(cardManager)

        val rotator = KeysRotator(
                this.crypto, this.privateKey, this.card.identifier,
                100, 5, 2, numberOfOneTimeKeys,
                fakeLongTermKeysStorage, fakeOneTimeKeysStorage, fakeClient
        )

        rotate(rotator, this.tokenProvider)

        Thread.sleep(6000)

        val log1 = rotate(rotator, this.tokenProvider)

        Assertions.assertEquals(1, log1.longTermKeysRelevant)
        Assertions.assertEquals(1, log1.longTermKeysAdded)
        Assertions.assertEquals(0, log1.longTermKeysDeleted)
        Assertions.assertEquals(1, log1.longTermKeysMarkedOutdated)
        Assertions.assertEquals(1, log1.longTermKeysOutdated)

        Assertions.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assertions.assertEquals(2, fakeLongTermKeysStorage.map.size)
        Assertions.assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        Assertions.assertEquals(identity, user.key)

        Assertions.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))

        Thread.sleep(2000)

        val log2 = rotate(rotator, this.tokenProvider)

        Assertions.assertEquals(1, log2.longTermKeysRelevant)
        Assertions.assertEquals(0, log2.longTermKeysAdded)
        Assertions.assertEquals(1, log2.longTermKeysDeleted)
        Assertions.assertEquals(0, log2.longTermKeysMarkedOutdated)
        Assertions.assertEquals(0, log2.longTermKeysOutdated)

        Assertions.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assertions.assertEquals(1, fakeLongTermKeysStorage.map.size)
        Assertions.assertEquals(1, fakeClient.users.size)

        Assertions.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
    }

    @Test
    fun rotate__used_one_time_key___should_recreate_key() {
        val numberOfOneTimeKeys = 5

        val fakeLongTermKeysStorage = InMemoryLongTermKeysStorage()
        val fakeOneTimeKeysStorage = InMemoryOneTimeKeysStorage()
        val fakeClient = InMemoryRatchetClient(this.cardManager)

        val rotator = KeysRotator(
                this.crypto, this.privateKey, this.card.identifier,
                5, 100, 100, numberOfOneTimeKeys,
                fakeLongTermKeysStorage, fakeOneTimeKeysStorage, fakeClient
        )

        rotate(rotator, this.tokenProvider)

        val token = this.generator.generateToken(this.identity)

        fakeClient.getPublicKeySet(token.identity, token.stringRepresentation()).get()

        val log1 = rotate(rotator, tokenProvider)

        Assertions.assertEquals(numberOfOneTimeKeys, log1.oneTimeKeysRelevant)
        Assertions.assertEquals(1, log1.oneTimeKeysAdded)
        Assertions.assertEquals(0, log1.oneTimeKeysDeleted)
        Assertions.assertEquals(1, log1.oneTimeKeysMarkedOrphaned)
        Assertions.assertEquals(1, log1.oneTimeKeysOrphaned)

        Assertions.assertEquals(numberOfOneTimeKeys + 1, fakeOneTimeKeysStorage.map.size)
        Assertions.assertEquals(1, fakeLongTermKeysStorage.map.size)

        Thread.sleep(6000)

        val log2 = rotate(rotator, this.tokenProvider)

        Assertions.assertEquals(numberOfOneTimeKeys, log2.oneTimeKeysRelevant)
        Assertions.assertEquals(0, log2.oneTimeKeysAdded)
        Assertions.assertEquals(1, log2.oneTimeKeysDeleted)
        Assertions.assertEquals(0, log2.oneTimeKeysMarkedOrphaned)
        Assertions.assertEquals(0, log2.oneTimeKeysOrphaned)

        Assertions.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assertions.assertEquals(1, fakeLongTermKeysStorage.map.size)
        Assertions.assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        Assertions.assertEquals(this.identity, user.key)

        Assertions.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
    }

    private fun rotate(rotator: KeysRotator, tokenProvider: AccessTokenProvider): RotationLog {
        val tokenContext = TokenContext("ratchet", false, "rotate")
        val jwt = tokenProvider.getToken(tokenContext)

        return rotator.rotateKeys(jwt).get()
    }

    private fun compareCloudAndStorage(
            userStore: InMemoryRatchetClient.UserStore,
            longTermStorage: InMemoryLongTermKeysStorage,
            oneTimeStorage: InMemoryOneTimeKeysStorage
    ): Boolean {

        val longTermKey = userStore.longTermPublicKey?.publicKey
        try {
            if (longTermKey != null) {
                val keyId = this.keyId.computePublicKeyId(longTermKey)

                if (!longTermStorage.retrieveKey(keyId).identifier.contentEquals(keyId)) {
                    logger.warning("Wrong long term key ID")
                    return false
                }

                val storedOneTimeKeysIds = oneTimeStorage.retrieveAllKeys().map { it.identifier }
                val cloudOneTimeKeysIds = userStore.oneTimePublicKeys.map { this.keyId.computePublicKeyId(it) }

                if (storedOneTimeKeysIds.size != cloudOneTimeKeysIds.size) {
                    logger.warning("One time keys cound doesn't match")
                    return false
                }
                storedOneTimeKeysIds.forEachIndexed { i, value ->
                    if (!cloudOneTimeKeysIds[i].contentEquals(value)) {
                        logger.warning("Could one time key $i doesn't match")
                        return false
                    }
                }
            }
        } catch (e: Exception) {
            logger.severe("Unpredictable error: $e")
            return false
        }

        return true
    }
    
    companion object {
        private val logger = Logger.getLogger(KeysRotatorTest::class.java.name)
    }
}