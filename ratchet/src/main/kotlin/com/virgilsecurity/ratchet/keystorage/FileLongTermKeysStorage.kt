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
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.*

class FileLongTermKeysStorage : LongTermKeysStorage {

    private val fileSystem: SecureFileSystem

    constructor(identity: String, crypto: VirgilCrypto, identityKeyPair: VirgilKeyPair, rootPath: Path? = null) {
        val credentials = SecureFileSystem.Credentials(crypto, identityKeyPair)
        fileSystem = SecureFileSystem(identity, rootPath, listOf("ltks"), credentials)
    }

    override fun storeKey(key: ByteArray, keyId: ByteArray): LongTermKey {
        val keyIdHex = String.format("%02X", keyId)
        val longTermKey = LongTermKey(keyId, key, Date())
        val data = SecureFileSystem.gson.toJson(longTermKey).toByteArray(StandardCharsets.UTF_8)
        fileSystem.write(keyIdHex, data)

        return longTermKey
    }

    override fun retrieveKey(keyId: ByteArray): LongTermKey {
        val keyIdHex = String.format("%02X", keyId)
        val data = fileSystem.read(keyIdHex)
        if (data.isEmpty()) {
            KeyStorageException(KeyStorageException.KEY_NOT_FOUND, "Long-term key $keyIdHex not found")
        }
        return SecureFileSystem.gson.fromJson(data.toString(StandardCharsets.UTF_8), LongTermKey::class.java)
    }

    override fun deleteKey(keyId: ByteArray) {
        val keyIdHex = String.format("%02X", keyId)
        this.fileSystem.delete(keyIdHex)
    }

    override fun retrieveAllKeys(): List<LongTermKey> {
        val allKeyIds = fileSystem.list()
        var allKeys = mutableListOf<LongTermKey>()
        allKeyIds.forEach {
            val keyIdHex = it.fileName.toString()
            val data = fileSystem.read(keyIdHex)
            allKeys.add(SecureFileSystem.gson.fromJson(data.toString(StandardCharsets.UTF_8), LongTermKey::class.java))
        }
        return allKeys
    }

    override fun markKeyOutdated(date: Date, keyId: ByteArray) {
        val keyIdHex = String.format("%02X", keyId)
        val longTermKey = retrieveKey(keyId)
        val newLongTermKey = LongTermKey(longTermKey.identifier, longTermKey.key, longTermKey.creationDate, Date())
        val data = SecureFileSystem.gson.toJson(longTermKey).toByteArray(StandardCharsets.UTF_8)
        fileSystem.write(keyIdHex, data)
    }

    override fun reset() {
        this.fileSystem.deleteDir()
    }

}