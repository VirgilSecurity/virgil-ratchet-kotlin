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

package com.virgilsecurity.ratchet

import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureSession
import org.junit.jupiter.api.Assertions
import kotlin.random.Random

class Utils {
    companion object {

        fun encryptDecrypt100Times(senderSession: SecureSession, receiverSession: SecureSession) {
            for (i in 1..100) {
                val sender: SecureSession
                val receiver: SecureSession

                if (Random.nextBoolean()) {
                    sender = senderSession
                    receiver = receiverSession
                } else {
                    sender = receiverSession
                    receiver = senderSession
                }

                val plainText = generateText()
                val message = sender.encrypt(plainText)
                val decryptedMessage = receiver.decryptString(message)

                Assertions.assertEquals(plainText, decryptedMessage)
            }
        }

        fun encryptDecrypt100TimesRestored(
                senderSecureChat: SecureChat,
                senderIdentity: String,
                receiverSecureChat: SecureChat,
                receiverIdentity: String
        ) {
            for (i in 1..100) {
                val sender: SecureSession
                val receiver: SecureSession

                if (Random.nextBoolean()) {
                    sender = senderSecureChat.existingSession(receiverIdentity)!!
                    receiver = receiverSecureChat.existingSession(senderIdentity)!!
                } else {
                    sender = receiverSecureChat.existingSession(senderIdentity)!!
                    receiver = senderSecureChat.existingSession(receiverIdentity)!!
                }

                val plainText = generateText()

                val message = sender.encrypt(plainText)

                val decryptedMessage = receiver.decryptString(message)

                Assertions.assertEquals(plainText, decryptedMessage)

            }
        }
    }
}
