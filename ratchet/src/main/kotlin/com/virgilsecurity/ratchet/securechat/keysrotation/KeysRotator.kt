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
import com.virgilsecurity.ratchet.client.RatchetClientInterface
import com.virgilsecurity.ratchet.data.SignedPublicKey
import com.virgilsecurity.ratchet.keystorage.LongTermKey
import com.virgilsecurity.ratchet.keystorage.LongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.OneTimeKeysStorage
import com.virgilsecurity.ratchet.utils.addSeconds
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.ratchet.utils.logger
import com.virgilsecurity.sdk.crypto.KeyType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.jwt.contract.AccessToken
import java.util.*
import kotlin.math.max

/**
 * Default implementation of KeysRotatorInterface.
 *
 * @param crypto VirgilCrypto instance
 * @param identityPrivateKey identity private key
 * @param identityCardId identity card id
 * @param orphanedOneTimeKeyTtl time that one-time key lives in the storage after been marked as orphaned. Seconds
 * @param longTermKeyTtl time that long-term key is been used before rotation. Seconds
 * @param outdatedLongTermKeyTtl time that long-term key lives in the storage after been marked as outdated. Seconds
 * @param desiredNumberOfOneTimeKeys desired number of one-time keys
 * @param longTermKeysStorage long-term keys storage
 * @param oneTimeKeysStorage one-time keys storage
 * @param client RatchetClient
 */
class KeysRotator(
        private val crypto: VirgilCrypto,
        private val identityPrivateKey: VirgilPrivateKey,
        private val identityCardId: String,
        private val orphanedOneTimeKeyTtl: Int,
        private val longTermKeyTtl: Int,
        private val outdatedLongTermKeyTtl: Int,
        private val desiredNumberOfOneTimeKeys: Int,
        private val longTermKeysStorage: LongTermKeysStorage,
        private val oneTimeKeysStorage: OneTimeKeysStorage,
        private val client: RatchetClientInterface
) : KeysRotatorInterface {

    private val keyId = RatchetKeyId()

    companion object {
        val LOG = logger()
    }

    /**
     * Rotate keys.
     *
     * Rotation process:
     * - Retrieve all one-time keys
     * - Delete one-time keys that were marked as orphaned more than orphanedOneTimeKeyTtl seconds ago
     * - Retrieve all long-term keys
     * - Delete long-term keys that were marked as outdated more than outdatedLongTermKeyTtl seconds ago
     * - Check that all relevant long-term and one-time keys are in the cloud
     *   (still persistent in the cloud and were not used)
     * - Mark used one-time keys as used
     * - Decide on long-term key roration
     * - Generate needed number of one-time keys
     * - Upload keys to the cloud
     *
     * @return rotation log
     */
    @Synchronized
    override fun rotateKeys(token: AccessToken): RotationLog {
        val now = Date()
        val rotationLog = RotationLog()

        this.oneTimeKeysStorage.startInteraction()
        try {

            val oneTimeKeys = this.oneTimeKeysStorage.retrieveAllKeys()
            var oneTimeKeysIds = mutableListOf<ByteArray>()

            oneTimeKeys.forEach {
                val orphanedFrom = it.orphanedFrom
                if (orphanedFrom != null) {
                    if (addSeconds(orphanedFrom, this.orphanedOneTimeKeyTtl) < now) {
                        LOG.value.fine("Removing orphaned one-time key ${it.identifier.hexEncodedString()}")
                        this.oneTimeKeysStorage.deleteKey(it.identifier)
                        rotationLog.oneTimeKeysDeleted += 1
                    } else {
                        rotationLog.oneTimeKeysOrphaned += 1
                    }
                } else {
                    oneTimeKeysIds.add(it.identifier)
                }
            }

            var numOfRelevantLongTermKeys = 0
            val longTermKeys = this.longTermKeysStorage.retrieveAllKeys()
            var lastLongTermKey: LongTermKey? = null
            longTermKeys.forEach {
                val oudatedFrom = it.outdatedFrom
                if (oudatedFrom != null) {
                    LOG.value.fine("LT key ${it.identifier.hexEncodedString()} is outdated")
                    if (addSeconds(oudatedFrom, this.outdatedLongTermKeyTtl) < now) {
                        LOG.value.fine("Removing outdated long-term key ${it.identifier.hexEncodedString()}")
                        this.longTermKeysStorage.deleteKey(it.identifier)
                        rotationLog.longTermKeysDeleted += 1
                    } else {
                        rotationLog.longTermKeysOutdated += 1
                    }
                } else {
                    if (addSeconds(it.creationDate, this.longTermKeyTtl) < now) {
                        LOG.value.fine("Marking long-term key as outdated ${it.identifier.hexEncodedString()}")
                        this.longTermKeysStorage.markKeyOutdated(now, it.identifier)
                        rotationLog.longTermKeysMarkedOutdated += 1
                        rotationLog.longTermKeysOutdated += 1
                    } else {
                        if (lastLongTermKey != null && lastLongTermKey!!.creationDate < it.creationDate) {
                            lastLongTermKey = it
                        }
                        if (lastLongTermKey == null) {
                            lastLongTermKey = it
                        }
                        numOfRelevantLongTermKeys += 1
                    }
                }
            }

            LOG.value.fine("Validating local keys")
            val validateResponse = this.client.validatePublicKeys(
                    lastLongTermKey?.identifier,
                    oneTimeKeysIds,
                    token.stringRepresentation()
            )

            validateResponse.usedOneTimeKeysIds.forEach {
                LOG.value.fine("Marking one-time key as orphaned ${it.hexEncodedString()}")
                this.oneTimeKeysStorage.markKeyOrphaned(now, it)
                rotationLog.oneTimeKeysMarkedOrphaned += 1
                rotationLog.oneTimeKeysOrphaned += 1
            }

            var rotateLongTermKey = false
            if (validateResponse.usedLongTermKeyId != null || lastLongTermKey == null) {
                rotateLongTermKey = true
            }
            if (lastLongTermKey != null && addSeconds(lastLongTermKey!!.creationDate, this.longTermKeyTtl) < now) {
                rotateLongTermKey = true
            }

            var longTermSignedPublicKey: SignedPublicKey? = null
            if (rotateLongTermKey) {
                LOG.value.fine("Rotating long-term key")
                val longTermKeyPair = this.crypto.generateKeyPair(KeyType.CURVE25519)
                val longTermPrivateKey = this.crypto.exportPrivateKey(longTermKeyPair.privateKey)
                val longTermPublicKey = this.crypto.exportPublicKey(longTermKeyPair.publicKey)
                val longTermKeyId = this.keyId.computePublicKeyId(longTermPublicKey)

                this.longTermKeysStorage.storeKey(longTermPrivateKey, longTermKeyId)
                val longTermKeySignature = this.crypto.generateSignature(longTermPublicKey, this.identityPrivateKey)
                longTermSignedPublicKey = SignedPublicKey(longTermPublicKey, longTermKeySignature)
            } else {
                longTermSignedPublicKey = null
            }

            val numOfRelevantOneTimeKeys = oneTimeKeysIds.size - validateResponse.usedOneTimeKeysIds.size
            val numbOfOneTimeKeysToGen = max(this.desiredNumberOfOneTimeKeys - numOfRelevantOneTimeKeys, 0)

            LOG.value.fine("Generating $numbOfOneTimeKeysToGen one-time keys")
            var oneTimePublicKeys: MutableList<ByteArray>
            if (numbOfOneTimeKeysToGen > 0) {
                var publicKeys = mutableListOf<ByteArray>()
                for (i in 1..numbOfOneTimeKeysToGen) {
                    LOG.value.fine("Generation $i key of $numbOfOneTimeKeysToGen")
                    val keyPair = this.crypto.generateKeyPair(KeyType.CURVE25519)
                    val oneTimePrivateKey = this.crypto.exportPrivateKey(keyPair.privateKey)
                    val oneTimePublicKey = this.crypto.exportPublicKey(keyPair.publicKey)
                    val keyId = this.keyId.computePublicKeyId(oneTimePublicKey)

                    this.oneTimeKeysStorage.storeKey(oneTimePrivateKey, keyId)
                    publicKeys.add(oneTimePublicKey)
                }

                oneTimePublicKeys = publicKeys
            } else {
                oneTimePublicKeys = mutableListOf()
            }

            LOG.value.fine("Uploading keys")
            this.client.uploadPublicKeys(
                    this.identityCardId, longTermSignedPublicKey, oneTimePublicKeys,
                    token.stringRepresentation()
            )

            rotationLog.oneTimeKeysAdded = oneTimePublicKeys.size
            rotationLog.oneTimeKeysRelevant = numOfRelevantOneTimeKeys + oneTimePublicKeys.size
            rotationLog.longTermKeysRelevant = numOfRelevantLongTermKeys + (if (longTermSignedPublicKey == null) 0 else 1)
            rotationLog.longTermKeysAdded = if (longTermSignedPublicKey == null) 0 else 1

        } finally {
//            this.oneTimeKeysStorage.stopInteraction()
        }
        return rotationLog
    }

}