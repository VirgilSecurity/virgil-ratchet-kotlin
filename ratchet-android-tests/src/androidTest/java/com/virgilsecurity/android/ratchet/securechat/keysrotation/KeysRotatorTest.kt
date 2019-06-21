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

package com.virgilsecurity.android.ratchet.securechat.keysrotation

import com.virgilsecurity.android.ratchet.*
import com.virgilsecurity.crypto.ratchet.RatchetKeyId
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.ratchet.securechat.keysrotation.RotationLog
import com.virgilsecurity.ratchet.utils.logger
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit
import java.util.logging.Level

class KeysRotatorTest {

    private lateinit var keyId: RatchetKeyId
    private lateinit var crypto: VirgilCrypto
    private lateinit var cardManager: CardManager
    private lateinit var tokenProvider: AccessTokenProvider
    private lateinit var generator: JwtGenerator
    private lateinit var identity: String
    private lateinit var privateKey: VirgilPrivateKey
    private lateinit var card: Card

    @Before
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

        assertEquals(1, log.longTermKeysRelevant)
        assertEquals(1, log.longTermKeysAdded)
        assertEquals(0, log.longTermKeysDeleted)
        assertEquals(0, log.longTermKeysMarkedOutdated)
        assertEquals(0, log.longTermKeysOutdated)
        assertEquals(numberOfOneTimeKeys, log.oneTimeKeysRelevant)
        assertEquals(numberOfOneTimeKeys, log.oneTimeKeysAdded)
        assertEquals(0, log.oneTimeKeysDeleted)
        assertEquals(0, log.oneTimeKeysMarkedOrphaned)
        assertEquals(0, log.oneTimeKeysOrphaned)
        assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        assertEquals(1, fakeLongTermKeysStorage.map.size)
        assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        assertEquals(this.identity, user.key)
        assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
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

        assertEquals(1, log1.longTermKeysRelevant)
        assertEquals(1, log1.longTermKeysAdded)
        assertEquals(0, log1.longTermKeysDeleted)
        assertEquals(1, log1.longTermKeysMarkedOutdated)
        assertEquals(1, log1.longTermKeysOutdated)

        assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        assertEquals(2, fakeLongTermKeysStorage.map.size)
        assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        assertEquals(identity, user.key)

        assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))

        Thread.sleep(2000)

        val log2 = rotate(rotator, this.tokenProvider)

        assertEquals(1, log2.longTermKeysRelevant)
        assertEquals(0, log2.longTermKeysAdded)
        assertEquals(1, log2.longTermKeysDeleted)
        assertEquals(0, log2.longTermKeysMarkedOutdated)
        assertEquals(0, log2.longTermKeysOutdated)

        assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        assertEquals(1, fakeLongTermKeysStorage.map.size)
        assertEquals(1, fakeClient.users.size)

        assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
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

        fakeClient.getPublicKeySet(token.identity, token.stringRepresentation())

        val log1 = rotate(rotator, tokenProvider)

        assertEquals(numberOfOneTimeKeys, log1.oneTimeKeysRelevant)
        assertEquals(1, log1.oneTimeKeysAdded)
        assertEquals(0, log1.oneTimeKeysDeleted)
        assertEquals(1, log1.oneTimeKeysMarkedOrphaned)
        assertEquals(1, log1.oneTimeKeysOrphaned)

        assertEquals(numberOfOneTimeKeys + 1, fakeOneTimeKeysStorage.map.size)
        assertEquals(1, fakeLongTermKeysStorage.map.size)

        Thread.sleep(6000)

        val log2 = rotate(rotator, this.tokenProvider)

        assertEquals(numberOfOneTimeKeys, log2.oneTimeKeysRelevant)
        assertEquals(0, log2.oneTimeKeysAdded)
        assertEquals(1, log2.oneTimeKeysDeleted)
        assertEquals(0, log2.oneTimeKeysMarkedOrphaned)
        assertEquals(0, log2.oneTimeKeysOrphaned)

        assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        assertEquals(1, fakeLongTermKeysStorage.map.size)
        assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        assertEquals(this.identity, user.key)

        assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
    }

    private fun rotate(rotator: KeysRotator, tokenProvider: AccessTokenProvider): RotationLog {
        val tokenContext = TokenContext("", false, "rotate")
        val jwt = tokenProvider.getToken(tokenContext)

        return rotator.rotateKeys(jwt)
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
                    LOG.value.warning("Wrong long term key ID")
                    return false
                }

                val storedOneTimeKeysIds = oneTimeStorage.retrieveAllKeys().map { it.identifier }
                val cloudOneTimeKeysIds = userStore.oneTimePublicKeys.map { this.keyId.computePublicKeyId(it) }

                if (storedOneTimeKeysIds.size != cloudOneTimeKeysIds.size) {
                    LOG.value.warning("One time keys cound doesn't match")
                    return false
                }
                storedOneTimeKeysIds.forEachIndexed { i, value ->
                    if (!cloudOneTimeKeysIds[i].contentEquals(value)) {
                        LOG.value.warning("Could one time key $i doesn't match")
                        return false
                    }
                }
            }
        } catch (e: Exception) {
            LOG.value.log(Level.SEVERE, "Unpredictable error", e)
            return false
        }

        return true
    }

    companion object {
        val LOG = logger()
    }
}