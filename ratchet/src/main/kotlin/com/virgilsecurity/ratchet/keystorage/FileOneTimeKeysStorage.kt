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

package com.virgilsecurity.ratchet.keystorage

import com.google.gson.annotations.SerializedName
import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.utils.SecureFileSystem
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.ratchet.utils.logger
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.nio.charset.StandardCharsets
import java.util.*

class FileOneTimeKeysStorage : OneTimeKeysStorage {

    private val fileSystem: SecureFileSystem
    private var oneTimeKeys: OneTimeKeys? = null
    private var interactionCounter = 0

    constructor(identity: String, crypto: VirgilCrypto, identityKeyPair: VirgilKeyPair, rootPath: String? = null) {
        val credentials = SecureFileSystem.Credentials(crypto, identityKeyPair)
        fileSystem = SecureFileSystem(identity, rootPath, listOf("otks"), credentials)
    }

    override fun startInteraction() {
        LOG.value.info("startInteraction")
        synchronized(interactionCounter) {
            if (interactionCounter > 0) {
                interactionCounter++
                return
            }

            if (oneTimeKeys != null) {
                throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should be null")
            }

            val data = fileSystem.read("OTK")

            oneTimeKeys = if (data.isNotEmpty()) {
                ConvertionUtils.getGson().fromJson(data.toString(StandardCharsets.UTF_8), OneTimeKeys::class.java)
            } else {
                OneTimeKeys()
            }

            interactionCounter = 1
        }
    }

    override fun stopInteraction() {
        LOG.value.info("stopInteraction")
        synchronized(interactionCounter) {
            if (interactionCounter <= 0) {
                throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "interactionCounter should be > 0")
            }

            interactionCounter--

            if (interactionCounter > 0) {
                return
            }

            if (oneTimeKeys == null) {
                KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should not be nil")
            }

            val data = ConvertionUtils.getGson().toJson(oneTimeKeys).toByteArray(StandardCharsets.UTF_8)

            fileSystem.write("OTK", data)
            oneTimeKeys = null
        }
    }

    override fun storeKey(key: ByteArray, keyId: ByteArray): OneTimeKey {
        LOG.value.fine("storeKey")
        synchronized(interactionCounter) {
            if (oneTimeKeys == null) {
                KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should not be nil")
            }

            val existedKey = oneTimeKeys!!.oneTimeKeys.firstOrNull { it.identifier.contentEquals(keyId) }
            if (existedKey != null) {
                throw KeyStorageException(KeyStorageException.KEY_ALREADY_EXISTS, "One time key already exists")
            }

            var oneTimeKey = OneTimeKey(keyId, key)
            oneTimeKeys!!.oneTimeKeys.add(oneTimeKey)

            return oneTimeKey
        }
    }

    override fun retrieveKey(keyId: ByteArray): OneTimeKey {
        if (this.oneTimeKeys == null) {
            throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should not be null")
        }

        val oneTimeKey =
                oneTimeKeys!!.oneTimeKeys.firstOrNull { it.identifier.contentEquals(keyId) }
                        ?: throw KeyStorageException(
                                KeyStorageException.KEY_NOT_FOUND,
                                "One time key doesn't exist"
                        )

        return oneTimeKey
    }

    override fun deleteKey(keyId: ByteArray) {
        synchronized(interactionCounter) {
            if (this.oneTimeKeys == null) {
                throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should not be null")
            }
            val oneTimeKeyIndex = oneTimeKeys!!.oneTimeKeys.indexOfFirst { it.identifier.contentEquals(keyId) }
            if (oneTimeKeyIndex < 0) {
                throw KeyStorageException(KeyStorageException.KEY_NOT_FOUND, "One time key doesn't exist")
            }

            oneTimeKeys!!.oneTimeKeys.removeAt(oneTimeKeyIndex)
            LOG.value.info("Key ${keyId.hexEncodedString()} removed")
        }
    }

    override fun retrieveAllKeys(): List<OneTimeKey> {
        if (this.oneTimeKeys == null) {
            throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should not be null")
        }
        return oneTimeKeys!!.oneTimeKeys.toList()
    }

    override fun markKeyOrphaned(date: Date, keyId: ByteArray) {
        synchronized(interactionCounter) {
            if (this.oneTimeKeys == null) {
                throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "oneTimeKeys should not be null")
            }

            val oneTimeKeyIndex = oneTimeKeys!!.oneTimeKeys.indexOfFirst { it.identifier.contentEquals(keyId) }
            if (oneTimeKeyIndex < 0) {
                throw KeyStorageException(KeyStorageException.KEY_NOT_FOUND, "One time key doesn't exist")
            }
            val oneTimeKey = oneTimeKeys!!.oneTimeKeys[oneTimeKeyIndex]
            if (oneTimeKey.orphanedFrom != null) {
                throw KeyStorageException(KeyStorageException.KEY_ALREADY_MARKED, "Key already marked as orphaned")
            }
            val newOneTimeKey = OneTimeKey(oneTimeKey.identifier, oneTimeKey.key, date)
            oneTimeKeys!!.oneTimeKeys[oneTimeKeyIndex] = newOneTimeKey
        }
    }

    override fun reset() {
        if (interactionCounter != 0) {
            throw KeyStorageException(KeyStorageException.ILLEGAL_STORAGE_STATE, "interactionCounter should be 0")
        }
        this.fileSystem.deleteDir()
    }

    companion object {
        val LOG = logger()
    }

    private class OneTimeKeys {
        @SerializedName("one_time_keys")
        var oneTimeKeys = mutableListOf<OneTimeKey>()
    }

}