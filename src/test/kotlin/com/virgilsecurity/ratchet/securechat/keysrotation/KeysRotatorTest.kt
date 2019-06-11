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
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

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
            VirgilCardClient(TestConfig.serviceURL)
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

        Assert.assertEquals(1, log.longTermKeysRelevant)
        Assert.assertEquals(1, log.longTermKeysAdded)
        Assert.assertEquals(0, log.longTermKeysDeleted)
        Assert.assertEquals(0, log.longTermKeysMarkedOutdated)
        Assert.assertEquals(0, log.longTermKeysOutdated)
        Assert.assertEquals(numberOfOneTimeKeys, log.oneTimeKeysRelevant)
        Assert.assertEquals(numberOfOneTimeKeys, log.oneTimeKeysAdded)
        Assert.assertEquals(0, log.oneTimeKeysDeleted)
        Assert.assertEquals(0, log.oneTimeKeysMarkedOrphaned)
        Assert.assertEquals(0, log.oneTimeKeysOrphaned)
        Assert.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assert.assertEquals(1, fakeLongTermKeysStorage.map.size)
        Assert.assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        Assert.assertEquals(this.identity, user.key)
        Assert.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
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

        Assert.assertEquals(1, log1.longTermKeysRelevant)
        Assert.assertEquals(1, log1.longTermKeysAdded)
        Assert.assertEquals(0, log1.longTermKeysDeleted)
        Assert.assertEquals(1, log1.longTermKeysMarkedOutdated)
        Assert.assertEquals(1, log1.longTermKeysOutdated)

        Assert.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assert.assertEquals(2, fakeLongTermKeysStorage.map.size)
        Assert.assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        Assert.assertEquals(identity, user.key)

        Assert.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))

        Thread.sleep(2000)

        val log2 = rotate(rotator, this.tokenProvider)

        Assert.assertEquals(1, log2.longTermKeysRelevant)
        Assert.assertEquals(0, log2.longTermKeysAdded)
        Assert.assertEquals(1, log2.longTermKeysDeleted)
        Assert.assertEquals(0, log2.longTermKeysMarkedOutdated)
        Assert.assertEquals(0, log2.longTermKeysOutdated)

        Assert.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assert.assertEquals(1, fakeLongTermKeysStorage.map.size)
        Assert.assertEquals(1, fakeClient.users.size)

        Assert.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
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

        Assert.assertEquals(numberOfOneTimeKeys, log1.oneTimeKeysRelevant)
        Assert.assertEquals(1, log1.oneTimeKeysAdded)
        Assert.assertEquals(0, log1.oneTimeKeysDeleted)
        Assert.assertEquals(1, log1.oneTimeKeysMarkedOrphaned)
        Assert.assertEquals(1, log1.oneTimeKeysOrphaned)

        Assert.assertEquals(numberOfOneTimeKeys + 1, fakeOneTimeKeysStorage.map.size)
        Assert.assertEquals(1, fakeLongTermKeysStorage.map.size)

        Thread.sleep(6000)

        val log2 = rotate(rotator, this.tokenProvider)

        Assert.assertEquals(numberOfOneTimeKeys, log2.oneTimeKeysRelevant)
        Assert.assertEquals(0, log2.oneTimeKeysAdded)
        Assert.assertEquals(1, log2.oneTimeKeysDeleted)
        Assert.assertEquals(0, log2.oneTimeKeysMarkedOrphaned)
        Assert.assertEquals(0, log2.oneTimeKeysOrphaned)

        Assert.assertEquals(numberOfOneTimeKeys, fakeOneTimeKeysStorage.map.size)
        Assert.assertEquals(1, fakeLongTermKeysStorage.map.size)
        Assert.assertEquals(1, fakeClient.users.size)

        val user = fakeClient.users.entries.first()
        Assert.assertEquals(this.identity, user.key)

        Assert.assertTrue(compareCloudAndStorage(user.value, fakeLongTermKeysStorage, fakeOneTimeKeysStorage))
    }

    private fun rotate(rotator: KeysRotator, tokenProvider: AccessTokenProvider): RotationLog {
        val tokenContext = TokenContext("ratchet", false, "rotate")
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
                    return false
                }

                val storedOneTimeKeysIds = oneTimeStorage.retrieveAllKeys().map { it.identifier }
                val cloudOneTimeKeysIds = userStore.oneTimePublicKeys.map { this.keyId.computePublicKeyId(it) }

                if (storedOneTimeKeysIds.size != cloudOneTimeKeysIds.size) {
                    return false
                }
                storedOneTimeKeysIds.forEachIndexed { i, value ->
                    if (!cloudOneTimeKeysIds[i].contentEquals(value)) {
                        return false
                    }
                }
            }
        } catch (e: Exception) {
            return false
        }

        return true
    }

}