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

package com.virgilsecurity.android.ratchet.keystorage

import com.virgilsecurity.android.ratchet.TestConfig
import com.virgilsecurity.android.ratchet.generateKeyId
import com.virgilsecurity.android.ratchet.generatePublicKeyData
import com.virgilsecurity.ratchet.exception.KeyStorageException
import com.virgilsecurity.ratchet.keystorage.FileLongTermKeysStorage
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.*

class FileLongTermKeysStorageTest {

    private val identity = UUID.randomUUID().toString()
    private val path = TestConfig.context.filesDir.absolutePath
    private lateinit var keyStorage: FileLongTermKeysStorage

    @Before
    fun setup() {
        val crypto = VirgilCrypto()
        this.keyStorage = FileLongTermKeysStorage(identity, crypto, crypto.generateKeyPair(), path)
    }

    @Test
    fun store() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()
        this.keyStorage.storeKey(keyData, keyId)

        val key = this.keyStorage.retrieveKey(keyId)
        assertNotNull(key)
        assertArrayEquals(keyId, key.identifier)
        assertArrayEquals(keyData, key.key)
    }

    @Test
    fun store_delete() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()
        this.keyStorage.storeKey(keyData, keyId)
        this.keyStorage.deleteKey(keyId)

        try {
            this.keyStorage.retrieveKey(keyId)
            fail("Key should be deleted")
        }
        catch (e : KeyStorageException) {
            assertEquals(KeyStorageException.KEY_NOT_FOUND, e.errorCode)
        }
    }

    @Test
    fun retrieveAllKeys() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()

        assertTrue(this.keyStorage.retrieveAllKeys().isEmpty())

        this.keyStorage.storeKey(keyData, keyId)

        val keys = this.keyStorage.retrieveAllKeys()
        assertEquals(1, keys.size)
        assertArrayEquals(keyId, keys.first().identifier)
        assertArrayEquals(keyData, keys.first().key)

        this.keyStorage.storeKey(generatePublicKeyData(),
                                 generateKeyId())
        this.keyStorage.storeKey(generatePublicKeyData(),
                                 generateKeyId())
        assertEquals(3, this.keyStorage.retrieveAllKeys().size)

        this.keyStorage.deleteKey(keyId)
        assertEquals(2, this.keyStorage.retrieveAllKeys().size)
    }

    @Test
    fun store_delete_retrieveAllKeys() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()
        this.keyStorage.storeKey(keyData, keyId)
        assertEquals(1, this.keyStorage.retrieveAllKeys().size)
        assertArrayEquals(keyId, this.keyStorage.retrieveAllKeys().first().identifier)

        this.keyStorage.deleteKey(keyId)

        assertTrue(this.keyStorage.retrieveAllKeys().isEmpty())
    }

    @Test
    fun markKeyOutdated() {
        val keyId = generateKeyId()
        val keyData = generatePublicKeyData()

        val cal = Calendar.getInstance()
        cal.set(Calendar.MILLISECOND, 0)
        val now = cal.time

        this.keyStorage.storeKey(keyData, keyId)

        this.keyStorage.markKeyOutdated(now, keyId)

        val key = this.keyStorage.retrieveKey(keyId)
        assertNotNull(key)
        assertArrayEquals(keyId, key.identifier)
        assertArrayEquals(keyData, key.key)
        assertEquals(now, key.outdatedFrom)
    }

}