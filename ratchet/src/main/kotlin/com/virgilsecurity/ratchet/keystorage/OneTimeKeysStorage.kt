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

import java.util.*

/**
 * One-time keys storage.
 */
interface OneTimeKeysStorage {

    /**
     * Starts interaction with storage.
     * This method should be called before any other interaction with storage.
     * This method can be called many times and works like a stack.
     */
    fun startInteraction()

    /**
     * Stops interaction with storage.
     * This method should be called after all interactions with storage.
     * This method can be called many times and works like a stack.
     */
    fun stopInteraction()

    /**
     * Stores key.
     *
     * @param key Private key.
     * @param keyId Key id.
     *
     * @return One-time private key.
     */
    fun storeKey(key: ByteArray, keyId: ByteArray): OneTimeKey

    /**
     * Retrieves key.
     *
     * @param keyId Key id.
     *
     * @return One-time private key.
     */
    fun retrieveKey(keyId: ByteArray): OneTimeKey

    /**
     * Deletes key.
     *
     * @param keyId Key id.
     */
    fun deleteKey(keyId: ByteArray)

    /**
     * Retrieves all keys.
     *
     * @return Returns all keys.
     */
    fun retrieveAllKeys(): List<OneTimeKey>

    /**
     * Marks key as orphaned.
     *
     * @param date Date from which we found out that this key is orphaned.
     * @param keyId Key id.
     */
    fun markKeyOrphaned(date: Date, keyId: ByteArray)

    /**
     * Deletes all keys.
     */
    fun reset()
}
