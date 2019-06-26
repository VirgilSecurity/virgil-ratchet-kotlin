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

import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import java.io.File

class SecureFileSystem constructor(
        val userIdentifier: String,
        val rootPath: String?,
        val pathComponents: List<String>?,
        val credentials: Credentials? = null
) {

    private val logHelper = LogHelper.instance()

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

    fun list(subDir: String? = null): List<String> {
        val path = getFullPath(null, subDir)
        val file = File(path)
        return file.listFiles().filter { it.isFile }.map { it.name }
    }

    fun delete(name: String, subDir: String? = null) {
        val filePath = getFullPath(name, subDir)
        val file = File(filePath)
        if (file.exists())
            file.delete()
    }

    fun deleteDir(subDir: String? = null) {
        val path = getFullPath(null, subDir)
        logHelper.logger.fine("Deleting directory $path")
        val file = File(path)
        file.deleteRecursively()
    }

    private fun createRatchetDirectory(): String {
        val workDirectory = StringBuilder(rootPath ?: System.getProperty("user.home"))
        val dir = workDirectory.append('/').append("VIRGIL-RATCHET").append('/').append(userIdentifier).toString()
        val file = File(dir)
        if (file.exists() && file.isDirectory) {
            // It's OK, directory already exists
        } else {
            // Create a directory
            logHelper.logger.fine("Creating directory ${file.absolutePath}")
            file.mkdirs()
        }
        return dir
    }

    private fun writeFile(path: String, data: ByteArray) {
        val dataToWrite = if (credentials == null || data.isEmpty()) {
            data
        } else {
            credentials.crypto.signThenEncrypt(data, credentials.keyPair.privateKey, credentials.keyPair.publicKey)
        }
        val file = File(path)
        if (!file.exists()) {
            logHelper.logger.info("File ${file.absolutePath} doesn't exist")
            if (!file.parentFile.exists()) {
                file.parentFile.mkdirs()
            }
            file.createNewFile()
        }
        logHelper.logger.fine("Writing to file ${file.absolutePath}")
        file.writeBytes(dataToWrite)
    }

    private fun readFile(path: String): ByteArray {
        val file = File(path)
        val data = if (file.exists()) {
            logHelper.logger.fine("Reading file ${file.absolutePath}")
            file.readBytes()
        } else {
            byteArrayOf()
        }

        return if (credentials == null || data.isEmpty()) {
            data
        } else {
            credentials.crypto.decryptThenVerify(data, credentials.keyPair.privateKey, credentials.keyPair.publicKey)
        }
    }

    private fun getFullPath(name: String?, subDir: String?): String {
        var path = StringBuilder(createRatchetDirectory())
        pathComponents?.forEach {
            path = path.append(File.separator).append(it)
        }
        if (subDir != null) {
            path = path.append(File.separator).append(subDir)
        }
        val file = File(path.toString())
        file.mkdirs()
        if (name != null) {
            path = path.append(File.separator).append(name)
        }
        return path.toString()
    }
}
