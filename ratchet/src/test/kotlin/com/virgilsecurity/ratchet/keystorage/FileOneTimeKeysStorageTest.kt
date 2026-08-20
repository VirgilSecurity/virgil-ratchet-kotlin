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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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

    /**
     * Concurrent interactions must be serialized by the storage monitor.
     *
     * Locking on the boxed `interactionCounter` gives a monitor whose identity changes with the
     * counter value, so `startInteraction` and `stopInteraction` do not exclude each other: one
     * thread clears `oneTimeKeys` while another is still using it, and the interaction counter
     * loses increments. Both surface here as ILLEGAL_STORAGE_STATE.
     */
    @Test
    fun concurrent_interactions_are_serialized() {
        val threadCount = 8
        val iterations = 30

        val pool = Executors.newFixedThreadPool(threadCount)
        val startGate = CountDownLatch(1)
        val failures = Collections.synchronizedList(mutableListOf<Throwable>())

        try {
            val tasks = (0 until threadCount).map {
                pool.submit {
                    startGate.await()
                    repeat(iterations) {
                        try {
                            this.keyStorage.startInteraction()
                            try {
                                val keyId = generateKeyId()
                                val keyData = generatePublicKeyData()

                                this.keyStorage.storeKey(keyData, keyId)
                                Assertions.assertArrayEquals(keyData, this.keyStorage.retrieveKey(keyId).key)
                                this.keyStorage.deleteKey(keyId)
                            } finally {
                                this.keyStorage.stopInteraction()
                            }
                        } catch (e: Throwable) {
                            failures.add(e)
                        }
                    }
                }
            }

            startGate.countDown()
            tasks.forEach { it.get(2, TimeUnit.MINUTES) }
        } finally {
            pool.shutdownNow()
        }

        Assertions.assertTrue(failures.isEmpty()) {
            "Concurrent interactions failed ${failures.size} time(s), first: ${failures.firstOrNull()}"
        }

        // Every startInteraction was matched by a stopInteraction, so the counter must be back to
        // zero. reset() is the only observer of that state and throws when it is not.
        this.keyStorage.reset()
    }

    /**
     * Nesting deeper than the [java.lang.Integer] cache (-128..127) used to hand out a freshly
     * boxed monitor on every call, which meant no mutual exclusion at all past 127.
     */
    @Test
    fun deeply_nested_interactions() {
        val depth = 200

        repeat(depth) {
            this.keyStorage.startInteraction()
        }

        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()
        this.keyStorage.storeKey(keyData, keyId)
        Assertions.assertArrayEquals(keyData, this.keyStorage.retrieveKey(keyId).key)

        repeat(depth) {
            this.keyStorage.stopInteraction()
        }

        // Counter unwound to zero, so the storage is idle again.
        this.keyStorage.startInteraction()
        Assertions.assertArrayEquals(keyData, this.keyStorage.retrieveKey(keyId).key)
        this.keyStorage.stopInteraction()
    }
}