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

import com.sun.xml.internal.ws.spi.db.BindingContextFactory.LOGGER
import com.virgilsecurity.crypto.ratchet.RatchetKeyId
import com.virgilsecurity.ratchet.client.RatchetClientInterface
import com.virgilsecurity.ratchet.data.SignedPublicKey
import com.virgilsecurity.ratchet.keystorage.LongTermKey
import com.virgilsecurity.ratchet.keystorage.LongTermKeysStorage
import com.virgilsecurity.ratchet.keystorage.OneTimeKeysStorage
import com.virgilsecurity.ratchet.model.Result
import com.virgilsecurity.ratchet.utils.LogHelper
import com.virgilsecurity.ratchet.utils.addSeconds
import com.virgilsecurity.ratchet.utils.hexEncodedString
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
    private val logHelper = LogHelper.instance()

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
    override fun rotateKeys(token: AccessToken) = object : Result<RotationLog> {
        override fun get(): RotationLog {

            val now = Date()
            val rotationLog = RotationLog()

            this@KeysRotator.oneTimeKeysStorage.startInteraction()
            try {

                val oneTimeKeys = this@KeysRotator.oneTimeKeysStorage.retrieveAllKeys()
                var oneTimeKeysIds = mutableListOf<ByteArray>()

                oneTimeKeys.forEach {
                    val orphanedFrom = it.orphanedFrom
                    if (orphanedFrom != null) {
                        if (addSeconds(orphanedFrom, this@KeysRotator.orphanedOneTimeKeyTtl) < now) {
                            logHelper.logger.fine("Removing orphaned one-time key ${it.identifier.hexEncodedString()}")
                            this@KeysRotator.oneTimeKeysStorage.deleteKey(it.identifier)
                            rotationLog.oneTimeKeysDeleted += 1
                        } else {
                            rotationLog.oneTimeKeysOrphaned += 1
                        }
                    } else {
                        oneTimeKeysIds.add(it.identifier)
                    }
                }

                var numOfRelevantLongTermKeys = 0
                val longTermKeys = this@KeysRotator.longTermKeysStorage.retrieveAllKeys()
                var lastLongTermKey: LongTermKey? = null
                longTermKeys.forEach {
                    val oudatedFrom = it.outdatedFrom
                    if (oudatedFrom != null) {
                        logHelper.logger.fine("LT key ${it.identifier.hexEncodedString()} is outdated")
                        if (addSeconds(oudatedFrom, this@KeysRotator.outdatedLongTermKeyTtl) < now) {
                            logHelper.logger.fine("Removing outdated long-term key ${it.identifier.hexEncodedString()}")
                            this@KeysRotator.longTermKeysStorage.deleteKey(it.identifier)
                            rotationLog.longTermKeysDeleted += 1
                        } else {
                            rotationLog.longTermKeysOutdated += 1
                        }
                    } else {
                        if (addSeconds(it.creationDate, this@KeysRotator.longTermKeyTtl) < now) {
                            logHelper.logger.fine("Marking long-term key as outdated ${it.identifier.hexEncodedString()}")
                            this@KeysRotator.longTermKeysStorage.markKeyOutdated(now, it.identifier)
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

                logHelper.logger.fine("Validating local keys")
                val validateResponse = this@KeysRotator.client.validatePublicKeys(
                        lastLongTermKey?.identifier,
                        oneTimeKeysIds,
                        token.stringRepresentation()
                ).get()

                validateResponse.usedOneTimeKeysIds.forEach {
                    logHelper.logger.fine("Marking one-time key as orphaned ${it.hexEncodedString()}")
                    this@KeysRotator.oneTimeKeysStorage.markKeyOrphaned(now, it)
                    rotationLog.oneTimeKeysMarkedOrphaned += 1
                    rotationLog.oneTimeKeysOrphaned += 1
                }

                var rotateLongTermKey = false
                if (validateResponse.usedLongTermKeyId != null || lastLongTermKey == null) {
                    rotateLongTermKey = true
                }
                if (lastLongTermKey != null
                        && addSeconds(lastLongTermKey!!.creationDate, this@KeysRotator.longTermKeyTtl) < now) {
                    rotateLongTermKey = true
                }

                var longTermSignedPublicKey: SignedPublicKey?
                if (rotateLongTermKey) {
                    logHelper.logger.fine("Rotating long-term key")
                    val longTermKeyPair = this@KeysRotator.crypto.generateKeyPair(KeyType.CURVE25519)
                    val longTermPrivateKey = this@KeysRotator.crypto.exportPrivateKey(longTermKeyPair.privateKey)
                    val longTermPublicKey = this@KeysRotator.crypto.exportPublicKey(longTermKeyPair.publicKey)
                    val longTermKeyId = this@KeysRotator.keyId.computePublicKeyId(longTermPublicKey)

                    this@KeysRotator.longTermKeysStorage.storeKey(longTermPrivateKey, longTermKeyId)
                    val longTermKeySignature =
                            this@KeysRotator.crypto.generateSignature(longTermPublicKey,
                                                                      this@KeysRotator.identityPrivateKey)
                    longTermSignedPublicKey = SignedPublicKey(longTermPublicKey, longTermKeySignature)
                } else {
                    longTermSignedPublicKey = null
                }

                val numOfRelevantOneTimeKeys = oneTimeKeysIds.size - validateResponse.usedOneTimeKeysIds.size
                val numbOfOneTimeKeysToGen =
                        max(this@KeysRotator.desiredNumberOfOneTimeKeys - numOfRelevantOneTimeKeys, 0)

                logHelper.logger.fine("Generating $numbOfOneTimeKeysToGen one-time keys")
                var oneTimePublicKeys: MutableList<ByteArray>
                if (numbOfOneTimeKeysToGen > 0) {
                    var publicKeys = mutableListOf<ByteArray>()
                    for (i in 1..numbOfOneTimeKeysToGen) {
                        logHelper.logger.fine("Generation $i key of $numbOfOneTimeKeysToGen")
                        val keyPair = this@KeysRotator.crypto.generateKeyPair(KeyType.CURVE25519)
                        val oneTimePrivateKey = this@KeysRotator.crypto.exportPrivateKey(keyPair.privateKey)
                        val oneTimePublicKey = this@KeysRotator.crypto.exportPublicKey(keyPair.publicKey)
                        val keyId = this@KeysRotator.keyId.computePublicKeyId(oneTimePublicKey)

                        this@KeysRotator.oneTimeKeysStorage.storeKey(oneTimePrivateKey, keyId)
                        publicKeys.add(oneTimePublicKey)
                    }

                    oneTimePublicKeys = publicKeys
                } else {
                    oneTimePublicKeys = mutableListOf()
                }

                logHelper.logger.fine("Uploading keys")
                this@KeysRotator.client.uploadPublicKeys(
                        this@KeysRotator.identityCardId, longTermSignedPublicKey, oneTimePublicKeys,
                        token.stringRepresentation()
                ).execute()

                rotationLog.oneTimeKeysAdded = oneTimePublicKeys.size
                rotationLog.oneTimeKeysRelevant = numOfRelevantOneTimeKeys + oneTimePublicKeys.size
                rotationLog.longTermKeysRelevant = numOfRelevantLongTermKeys + (if (longTermSignedPublicKey == null) 0 else 1)
                rotationLog.longTermKeysAdded = if (longTermSignedPublicKey == null) 0 else 1

            } finally {
                this@KeysRotator.oneTimeKeysStorage.stopInteraction()
            }
            return rotationLog
        }
    }
}
