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

package com.virgilsecurity.ratchet.keystorage

import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.generateKeyId
import com.virgilsecurity.ratchet.generatePublicKeyData
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*

class FileOneTimeKeysStorageTest {

    private val identity = UUID.randomUUID().toString()
    private val path = createTempDir().absolutePath
    private lateinit var keyStorage: FileOneTimeKeysStorage

    @BeforeEach
    fun setup() {
        val crypto = VirgilCrypto()
        this.keyStorage = FileOneTimeKeysStorage(identity, crypto, crypto.generateKeyPair(), path)
    }

    @Test
    fun startInteraction() {
        this.keyStorage.startInteraction()
    }

    @Test
    fun stopInteraction_noStart() {
        try {
            this.keyStorage.stopInteraction()
        } catch (e: KeyStorageException) {
            Assertions.assertEquals(KeyStorageException.ILLEGAL_STORAGE_STATE, e.errorCode)
        }
    }

    @Test
    fun start_stopInteraction() {
        this.keyStorage.startInteraction()
        this.keyStorage.startInteraction()
    }

    @Test
    fun store_read() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()

        this.keyStorage.startInteraction()
        this.keyStorage.storeKey(keyData, keyId)

        val key = this.keyStorage.retrieveKey(keyId)
        Assertions.assertNotNull(key)
        Assertions.assertArrayEquals(keyId, key.identifier)
        Assertions.assertArrayEquals(keyData, key.key)
        this.keyStorage.stopInteraction()
    }

    @Test
    fun store_delete_many() {
        val keys = mutableMapOf<ByteArray, ByteArray>()

        this.keyStorage.startInteraction()
        for (i in 1 until 10) {
            val keyId = generateKeyId()
            val keyData = generatePublicKeyData()
            keys[keyId] = keyData

            this.keyStorage.storeKey(keyData, keyId)
        }

        // Store keys
        keys.forEach { (keyId, keyData) ->
            val key = this.keyStorage.retrieveKey(keyId)
            Assertions.assertNotNull(key)
            Assertions.assertArrayEquals(keyId, key.identifier)
            Assertions.assertArrayEquals(keyData, key.key)
        }

        // Remove first and last keys
        val removedKeyIds = mutableSetOf(keys.keys.first(), keys.keys.last())
        removedKeyIds.forEach { keyId ->
            this.keyStorage.deleteKey(keyId)
        }

        // Removed keys should not exist
        removedKeyIds.forEach { keyId ->
            try {
                this.keyStorage.retrieveKey(keyId)
                Assertions.fail("Key should be deleted")
            } catch (e: KeyStorageException) {
                Assertions.assertEquals(KeyStorageException.KEY_NOT_FOUND, e.errorCode)
            }
        }

        // Other keys should exist
        var cnt = 0
        keys.forEach { (keyId, keyData) ->
            try {
                val key = this.keyStorage.retrieveKey(keyId)
                Assertions.assertNotNull(key)
                Assertions.assertArrayEquals(keyId, key.identifier)
                Assertions.assertArrayEquals(keyData, key.key)
            } catch (e: KeyStorageException) {
                cnt++
            }
        }
        Assertions.assertEquals(2, cnt)

        this.keyStorage.stopInteraction()
    }

    @Test
    fun store_delete() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()

        this.keyStorage.startInteraction()
        this.keyStorage.storeKey(keyData, keyId)
        this.keyStorage.deleteKey(keyId)

        try {
            this.keyStorage.retrieveKey(keyId)
            Assertions.fail<String>("Key should be deleted")
        } catch (e: KeyStorageException) {
            Assertions.assertEquals(KeyStorageException.KEY_NOT_FOUND, e.errorCode)
        }
        this.keyStorage.stopInteraction()
    }

    @Test
    fun store_delete_retrieveAll() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()

        this.keyStorage.startInteraction()
        this.keyStorage.storeKey(keyData, keyId)
        this.keyStorage.deleteKey(keyId)
        Assertions.assertTrue(this.keyStorage.retrieveAllKeys().isEmpty())
        this.keyStorage.stopInteraction()
    }

    @Test
    fun read_not_exists() {
        this.keyStorage.startInteraction()
        val keyId = generateKeyId()
        try {
            this.keyStorage.retrieveKey(keyId)
            Assertions.fail<String>("Key should be deleted")
        } catch (e: KeyStorageException) {
            Assertions.assertEquals(KeyStorageException.KEY_NOT_FOUND, e.errorCode)
        }
        this.keyStorage.stopInteraction()
    }

    @Test
    fun read_not_initialized() {
        val keyId = generateKeyId()
        try {
            this.keyStorage.retrieveKey(keyId)
            Assertions.fail<String>("Key should be deleted")
        } catch (e: KeyStorageException) {
            Assertions.assertEquals(KeyStorageException.ILLEGAL_STORAGE_STATE, e.errorCode)
        }
    }

    @Test
    fun store_stop_start_read() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()

        this.keyStorage.startInteraction()
        this.keyStorage.storeKey(keyData, keyId)
        this.keyStorage.stopInteraction()

        this.keyStorage.startInteraction()
        val key = this.keyStorage.retrieveKey(keyId)
        Assertions.assertNotNull(key)
        Assertions.assertArrayEquals(keyId, key.identifier)
        Assertions.assertArrayEquals(keyData, key.key)
        this.keyStorage.stopInteraction()
    }
}