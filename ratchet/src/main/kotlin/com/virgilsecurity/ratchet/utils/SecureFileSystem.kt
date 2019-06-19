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

import com.google.gson.GsonBuilder
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.streams.toList

class SecureFileSystem(
    val userIdentifier: String,
    val rootPath: Path?,
    val pathComponents: List<String>?,
    val credentials: Credentials? = null
) {

    class Credentials(
        val crypto: VirgilCrypto,
        val keyPair: VirgilKeyPair
    )

    fun write(name: String, data: ByteArray, subDir: String? = null) {
        val path = getFullPath(name, subDir)
        writeFile(path, data)
    }

    fun read(name: String, subDir: String? = null): ByteArray {
        val path = getFullPath(name, subDir)
        return readFile(path)
    }

    fun list(subDir: String? = null): List<Path> {
        val path = getFullPath(null, subDir)
        return Files.list(path).filter { it.toFile().isFile }.toList()
    }

    fun delete(name: String, subDir: String? = null) {
        val filePath = getFullPath(name, subDir)
        Files.deleteIfExists(filePath)
    }

    fun deleteDir(subDir: String? = null) {
        val path = getFullPath(null, subDir)
        path.toFile().deleteRecursively()
    }

    private fun createRatchetDirectory(): Path {
        val workDirectory = rootPath ?: Paths.get(System.getProperty("user.home"))
        val dir = workDirectory.resolve("VIRGIL-RATCHET").resolve(userIdentifier)
        if (Files.exists(dir) && Files.isDirectory(dir)) {
            // It's OK, directory is already exists
        } else {
            // Create a directory
            Files.createDirectories(dir)
        }
        return dir
    }

    private fun writeFile(path: Path, data: ByteArray) {
        val dataToWrite = if (credentials == null || data.isEmpty()) {
            data
        } else {
            credentials.crypto.signThenEncrypt(data, credentials.keyPair.privateKey, credentials.keyPair.publicKey)
        }
        Files.write(path, dataToWrite)
    }

    private fun readFile(path: Path): ByteArray {
        var data = try {
            Files.readAllBytes(path)
        } catch (e: NoSuchFileException) {
            byteArrayOf()
        }

        return if (credentials == null || data.isEmpty()) {
            data
        } else {
            credentials.crypto.decryptThenVerify(data, credentials.keyPair.privateKey, credentials.keyPair.publicKey)
        }
    }

    private fun getFullPath(name: String?, subDir: String?): Path {
        var path = createRatchetDirectory()
        pathComponents?.forEach {
            path = path.resolve(it)
        }
        if (subDir != null) {
            path = path.resolve(subDir)
        }
        Files.createDirectories(path)
        if (name != null) {
            path = path.resolve(name)
        }
        return path
    }
}
