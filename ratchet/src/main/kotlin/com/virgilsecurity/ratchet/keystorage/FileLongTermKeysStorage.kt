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

import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.utils.SecureFileSystem
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * FileLongTermKeysStorage is used to store long-term keys.
 */
class FileLongTermKeysStorage(
        identity: String,
        crypto: VirgilCrypto,
        identityKeyPair: VirgilKeyPair,
        rootPath: String? = null
) : LongTermKeysStorage {

    private val fileSystem: SecureFileSystem

    init {
        val credentials = SecureFileSystem.Credentials(crypto, identityKeyPair)
        fileSystem = SecureFileSystem(identity, rootPath, listOf(LONG_TIME_KEY_STORAGE), credentials)
    }

    override fun storeKey(key: ByteArray, keyId: ByteArray): LongTermKey {
        val keyIdHex = keyId.hexEncodedString()
        val longTermKey = LongTermKey(keyId, key, Date())
        val data = ConvertionUtils.getGson().toJson(longTermKey).toByteArray(StandardCharsets.UTF_8)
        fileSystem.write(keyIdHex, data)

        return longTermKey
    }

    override fun retrieveKey(keyId: ByteArray): LongTermKey {
        val keyIdHex = keyId.hexEncodedString()
        val data = fileSystem.read(keyIdHex)
        if (data.isEmpty()) {
            throw KeyStorageException(KeyStorageException.KEY_NOT_FOUND, "Long-term key $keyIdHex not found")
        }
        return ConvertionUtils.getGson().fromJson(data.toString(StandardCharsets.UTF_8), LongTermKey::class.java)
    }

    override fun deleteKey(keyId: ByteArray) {
        val keyIdHex = keyId.hexEncodedString()
        this.fileSystem.delete(keyIdHex)
    }

    override fun retrieveAllKeys(): List<LongTermKey> {
        val allKeyIds = fileSystem.list()
        val allKeys = mutableListOf<LongTermKey>()
        allKeyIds.forEach { keyIdHex ->
            val data = fileSystem.read(keyIdHex)
            allKeys.add(ConvertionUtils.getGson().fromJson(data.toString(StandardCharsets.UTF_8), LongTermKey::class.java))
        }
        return allKeys
    }

    override fun markKeyOutdated(date: Date, keyId: ByteArray) {
        val keyIdHex = keyId.hexEncodedString()
        val longTermKey = retrieveKey(keyId)
        val newLongTermKey = LongTermKey(longTermKey.identifier, longTermKey.key, longTermKey.creationDate, date)
        val data = ConvertionUtils.getGson().toJson(newLongTermKey).toByteArray(StandardCharsets.UTF_8)
        fileSystem.write(keyIdHex, data)
    }

    override fun reset() {
        this.fileSystem.deleteDir()
    }

    companion object {
        private const val LONG_TIME_KEY_STORAGE = "ltks"
    }
}
