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

package com.virgilsecurity.ratchet.utils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*

class SecureFileSystemTest {
    private val identity = UUID.randomUUID().toString()
    private val path = createTempDir().absolutePath
    private lateinit var secureFileSystem: SecureFileSystem

    @BeforeEach
    fun setup() {
        secureFileSystem = SecureFileSystem(identity, path, null)
    }

    @Test
    fun write_then_read() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        val dataFromFile = secureFileSystem.read(name)
        Assertions.assertNotNull(dataFromFile)
        Assertions.assertArrayEquals(data, dataFromFile)
    }

    @Test
    fun write_then_deleteFile() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        Assertions.assertTrue(secureFileSystem.read(name).isNotEmpty())
        secureFileSystem.delete(name)
        Assertions.assertTrue(secureFileSystem.read(name).isEmpty())
    }

    @Test
    fun write_then_deleteDir() {
        val data = UUID.randomUUID().toString().toByteArray()
        val name = UUID.randomUUID().toString()

        secureFileSystem.write(name, data)
        Assertions.assertTrue(secureFileSystem.read(name).isNotEmpty())
        secureFileSystem.deleteDir()
        Assertions.assertTrue(secureFileSystem.read(name).isEmpty())
    }
}
