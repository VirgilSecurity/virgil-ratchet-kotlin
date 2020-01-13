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

import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.crypto.ratchet.RatchetKeyId
import com.virgilsecurity.ratchet.client.RatchetClientInterface
import com.virgilsecurity.ratchet.client.data.IdentityPublicKeySet
import com.virgilsecurity.ratchet.client.data.PublicKeySet
import com.virgilsecurity.ratchet.client.data.SignedPublicKey
import com.virgilsecurity.ratchet.client.data.ValidatePublicKeysResponse
import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.keystorage.LongTermKey
import com.virgilsecurity.ratchet.keystorage.LongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.OneTimeKey
import com.virgilsecurity.ratchet.keystorage.OneTimeKeysStorage
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.ratchet.securechat.SecureGroupSession
import com.virgilsecurity.ratchet.securechat.SecureSession
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotatorInterface
import com.virgilsecurity.ratchet.securechat.keysrotation.RotationLog
import com.virgilsecurity.ratchet.sessionstorage.GroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.CardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.crypto.HashAlgorithm
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.contract.AccessToken
import com.virgilsecurity.sdk.utils.Tuple
import java.util.*
import java.util.logging.Logger

class InMemorySessionStorage : SessionStorage {
    val map = mutableMapOf<String, SecureSession>()

    override fun storeSession(session: SecureSession) {
        this.map[session.participantIdentity] = session
    }

    override fun retrieveSession(participantIdentity: String, name: String): SecureSession? {
        return this.map[participantIdentity]
    }

    override fun deleteSession(participantIdentity: String, name: String?) {
        this.map.remove(participantIdentity)
    }

    override fun reset() {
        map.clear()
    }
}

class InMemoryGroupSessionStorage : GroupSessionStorage {
    val map = mutableMapOf<String, SecureGroupSession>()

    override fun storeSession(session: SecureGroupSession) {
        this.map[session.identifier().hexEncodedString()] = session
    }

    override fun retrieveSession(identifier: ByteArray): SecureGroupSession? {
        return this.map[identifier.hexEncodedString()]
    }

    override fun deleteSession(identifier: ByteArray) {
        val hexId = identifier.hexEncodedString()
        this.map.remove(hexId) ?: throw RuntimeException("Session $hexId not found")
    }

    override fun reset() {
        this.map.clear()
    }
}

class InMemoryLongTermKeysStorage : LongTermKeysStorage {
    val map = mutableMapOf<String, LongTermKey>()

    override fun storeKey(key: ByteArray, keyId: ByteArray): LongTermKey {
        val longTermKey = LongTermKey(keyId, key, Date())
        this.map[keyId.hexEncodedString()] = longTermKey
        return longTermKey
    }

    override fun retrieveKey(keyId: ByteArray): LongTermKey {
        val hex = keyId.hexEncodedString()
        if (!this.map.containsKey(hex)) {
            KeyStorageException(KeyStorageException.KEY_NOT_FOUND)
        }
        return this.map[hex]!!
    }

    override fun deleteKey(keyId: ByteArray) {
        this.map.remove(keyId.hexEncodedString())
    }

    override fun retrieveAllKeys(): List<LongTermKey> {
        return this.map.values.toList()
    }

    override fun markKeyOutdated(date: Date, keyId: ByteArray) {
        val hex = keyId.hexEncodedString()
        if (!this.map.containsKey(hex)) {
            KeyStorageException(KeyStorageException.KEY_NOT_FOUND)
        }
        val longTermKey = this.map[hex]!!
        this.map[hex] = LongTermKey(keyId, longTermKey.key, longTermKey.creationDate, date)
    }

    override fun reset() {
        this.map.clear()
    }
}

class InMemoryOneTimeKeysStorage : OneTimeKeysStorage {
    val map: MutableMap<String, OneTimeKey> = mutableMapOf()

    override fun startInteraction() {
    }

    override fun stopInteraction() {
    }

    override fun storeKey(key: ByteArray, keyId: ByteArray): OneTimeKey {
        val hexKey = keyId.hexEncodedString()
        logger.info("Store key: $hexKey")
        val oneTimeKey = OneTimeKey(keyId, key)
        this.map[hexKey] = oneTimeKey
        return oneTimeKey
    }

    override fun retrieveKey(keyId: ByteArray): OneTimeKey {
        val hexKey = keyId.hexEncodedString()
        if (!this.map.containsKey(hexKey)) {
            throw KeyStorageException(KeyStorageException.KEY_NOT_FOUND)
        }
        return this.map[hexKey]!!
    }

    override fun deleteKey(keyId: ByteArray) {
        val hexKey = keyId.hexEncodedString()
        logger.info("Delete key: $hexKey")
        if (!this.map.containsKey(hexKey)) {
            throw KeyStorageException(KeyStorageException.KEY_NOT_FOUND)
        }
        this.map.remove(hexKey)
    }

    override fun retrieveAllKeys(): List<OneTimeKey> {
        return this.map.values.toList()
    }

    override fun markKeyOrphaned(date: Date, keyId: ByteArray) {
        val hexKey = keyId.hexEncodedString()
        logger.info("Mark key orphaned: $hexKey")
        if (!this.map.containsKey(hexKey)) {
            throw KeyStorageException(KeyStorageException.KEY_NOT_FOUND)
        }
        val oneTimeKey = this.map[hexKey]!!
        this.map[hexKey] = OneTimeKey(keyId, oneTimeKey.key, date)
    }

    override fun reset() {
        this.map.clear()
    }

    companion object {
        private val logger = Logger.getLogger(InMemoryOneTimeKeysStorage::class.java.name)
    }
}

class FakeKeysRotator : KeysRotatorInterface {
    override fun rotateKeys(token: AccessToken): Result<RotationLog> {
        return object : Result<RotationLog> {
            override fun get(): RotationLog {
                return RotationLog()
            }
        }
    }
}

class TrustAllCardVerifier : CardVerifier {
    override fun verifyCard(card: Card?): Boolean {
        return true
    }
}

class InMemoryRatchetClient(private val cardManager: CardManager) : RatchetClientInterface {

    inner class UserStore {
        var identityPublicKey: VirgilPublicKey? = null
        var identityPublicKeyData: ByteArray? = null
        var longTermPublicKey: SignedPublicKey? = null
        var oneTimePublicKeys: MutableSet<ByteArray> = mutableSetOf()
    }

    private val keyId = RatchetKeyId()
    private val crypto = VirgilCrypto()
    var users = mutableMapOf<String, UserStore>()

    override fun uploadPublicKeys(
            identityCardId: String?,
            longTermPublicKey: SignedPublicKey?,
            oneTimePublicKeys: List<ByteArray>,
            token: String
    ) = object : Completable {
        override fun execute() {
            val jwt = Jwt(token)
            val userStore = this@InMemoryRatchetClient.users[jwt.identity] ?: UserStore()

            val publicKey: VirgilPublicKey
            if (identityCardId != null) {
                val card = this@InMemoryRatchetClient.cardManager.getCard(identityCardId)
                publicKey = card.publicKey as VirgilPublicKey
                userStore.identityPublicKey = publicKey
                userStore.identityPublicKeyData = this@InMemoryRatchetClient.crypto.exportPublicKey(publicKey)
            } else {
                if (userStore.identityPublicKey == null) {
                    throw RuntimeException("Identity public key is null")
                }

                publicKey = userStore.identityPublicKey!!
            }

            if (longTermPublicKey != null) {
                this@InMemoryRatchetClient.crypto.verifySignature(longTermPublicKey.signature,
                                                                  longTermPublicKey.publicKey, publicKey)

                userStore.longTermPublicKey = longTermPublicKey
            } else {
                if (userStore.longTermPublicKey == null) {
                    throw RuntimeException("Long term key is null")
                }
            }

            if (oneTimePublicKeys.isNotEmpty()) {
                val newKeysSet = mutableSetOf<ByteArray>()
                newKeysSet.addAll(oneTimePublicKeys)

                if (userStore.oneTimePublicKeys.intersect(newKeysSet).isNotEmpty()) {
                    throw RuntimeException("Some one time keys are already set")
                }

                userStore.oneTimePublicKeys.addAll(newKeysSet)
            }

            this@InMemoryRatchetClient.users[jwt.identity] = userStore
        }
    }

    override fun validatePublicKeys(
            longTermKeyId: ByteArray?,
            oneTimeKeysIds: List<ByteArray>,
            token: String
    ) = object : Result<ValidatePublicKeysResponse> {
        override fun get(): ValidatePublicKeysResponse {
            val jwt = Jwt(token)
            val userStore = this@InMemoryRatchetClient.users[jwt.identity] ?: UserStore()

            val usedLongTermKeyId: ByteArray?

            if (longTermKeyId != null && userStore.longTermPublicKey?.publicKey != null &&
                    this@InMemoryRatchetClient.keyId.computePublicKeyId(userStore.longTermPublicKey!!.publicKey)!!.contentEquals(longTermKeyId)
            ) {
                usedLongTermKeyId = null
            } else {
                usedLongTermKeyId = longTermKeyId
            }

            val validOneTimeKeysId = userStore.oneTimePublicKeys.map { this@InMemoryRatchetClient.keyId.computePublicKeyId(it).hexEncodedString() }
            val usedOneTimeKeysIds = oneTimeKeysIds.filter { !validOneTimeKeysId.contains(it.hexEncodedString()) }.toList()

            return ValidatePublicKeysResponse(usedLongTermKeyId, usedOneTimeKeysIds)
        }
    }

    override fun getPublicKeySet(identity: String, token: String) = object : Result<PublicKeySet> {
        override fun get(): PublicKeySet {
            Jwt(token)
            val userStore = this@InMemoryRatchetClient.users[identity] ?: UserStore()

            val identityPublicKey = userStore.identityPublicKeyData
            val longTermPublicKey = userStore.longTermPublicKey
            if (identityPublicKey == null || longTermPublicKey == null) {
                throw RuntimeException()
            }

            val oneTimePublicKey = userStore.oneTimePublicKeys.firstOrNull()
            if (oneTimePublicKey != null) {
                userStore.oneTimePublicKeys.remove(oneTimePublicKey)
                this@InMemoryRatchetClient.users[identity] = userStore
            }

            return PublicKeySet(identityPublicKey, longTermPublicKey, oneTimePublicKey)
        }
    }

    override fun getMultiplePublicKeysSets(identities: List<String>, token: String)
            = object : Result<List<IdentityPublicKeySet>> {
        override fun get(): List<IdentityPublicKeySet> {
            returnNothing()
        }
    }

    override fun deleteKeysEntity(token: String) = object : Completable {
        override fun execute() {
            this@InMemoryRatchetClient.users.clear()
        }
    }
}

class InMemoryCardClient : VirgilCardClient(TestConfig.cardsServiceURL) {
    private val crypto = VirgilCrypto()
    private val cards = mutableMapOf<String, RawSignedModel>()

    override fun getCard(cardId: String?, token: String?): Tuple<RawSignedModel, Boolean> {
        if (this.cards.containsKey(cardId)) {
            logger.info("Card $cardId exists")
        } else {
            val cardIds = this.cards.keys.joinToString()
            logger.warning("No card $cardId betwee $cardIds")
        }
        val rawCard = this.cards[cardId] ?: throw RuntimeException("Card $cardId not found")
        return Tuple(rawCard, false)
    }

    override fun searchCards(identity: String?, token: String?): MutableList<RawSignedModel> {
        returnNothing()
    }

    override fun searchCards(identities: MutableCollection<String>?, token: String?): MutableList<RawSignedModel> {
        returnNothing()
    }

    override fun publishCard(rawCard: RawSignedModel?, token: String?): RawSignedModel {
        val cardId = this.crypto.computeHash(rawCard?.contentSnapshot, HashAlgorithm.SHA512).copyOfRange(0, 32)
                .hexEncodedString()
        logger.info("Publish card $cardId")

        this.cards[cardId] = rawCard!!

        return rawCard
    }

    override fun revokeCard(cardId: String?, token: String?) {
        returnNothing()
    }

    companion object {
        private val logger = Logger.getLogger(InMemoryCardClient::class.java.name)
    }
}

fun generateIdentity(): String {
    return UUID.randomUUID().toString()
}

fun generateText(): String {
    return UUID.randomUUID().toString()
}

fun generateKeyId(): ByteArray {
    val crypto = VirgilCrypto()
    val keyPair = crypto.generateKeyPair(KeyPairType.CURVE25519)
    return keyPair.publicKey.identifier
}

fun generatePrivateKeyData(): ByteArray {
    val crypto = VirgilCrypto()
    val keyPair = crypto.generateKeyPair(KeyPairType.CURVE25519)
    return crypto.exportPrivateKey(keyPair.privateKey)
}

fun generatePublicKeyData(): ByteArray {
    val crypto = VirgilCrypto()
    val keyPair = crypto.generateKeyPair(KeyPairType.CURVE25519)
    return crypto.exportPublicKey(keyPair.publicKey)
}

private fun returnNothing(): Nothing =
    throw NotImplementedError("This method is supposed to not be called.")
