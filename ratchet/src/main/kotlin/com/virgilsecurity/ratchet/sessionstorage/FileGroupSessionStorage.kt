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

package com.virgilsecurity.ratchet.sessionstorage

import com.virgilsecurity.ratchet.securechat.SecureGroupSession
import com.virgilsecurity.ratchet.utils.SecureFileSystem
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair

/**
 * GroupSessionStorage implementation using files.
 *
 * @constructor Create new instance with: [identity] - Identity of this user, [crypto] - VirgilCrypto that will be
 * forwarded to SecureSession, [identityKeyPair] - Key pair to encrypt session, [rootPath] - Root path.
 */
class FileGroupSessionStorage(
        identity: String,
        private val crypto: VirgilCrypto,
        identityKeyPair: VirgilKeyPair,
        rootPath: String? = null
) : GroupSessionStorage {

    private val fileSystem: SecureFileSystem
    private val privateKeyData: ByteArray = crypto.exportPrivateKey(identityKeyPair.privateKey)

    init {
        val credentials = SecureFileSystem.Credentials(crypto, identityKeyPair)
        this.fileSystem = SecureFileSystem(identity, rootPath, listOf("GROUPS"), credentials)
    }

    override fun storeSession(session: SecureGroupSession) {
        synchronized(this.fileSystem) {
            val data = session.serialize()
            this.fileSystem.write(session.identifier().hexEncodedString(), data)
        }
    }

    override fun retrieveSession(identifier: ByteArray): SecureGroupSession? {
        val data = this.fileSystem.read(identifier.hexEncodedString())

        if (data.isEmpty()) {
            return null
        }

        return SecureGroupSession(data, privateKeyData, this.crypto)
    }

    override fun deleteSession(identifier: ByteArray) {
        synchronized(this.fileSystem) {
            this.fileSystem.delete(identifier.hexEncodedString())
        }
    }

    override fun reset() {
        synchronized(this.fileSystem) {
            this.fileSystem.deleteDir()
        }
    }
}
