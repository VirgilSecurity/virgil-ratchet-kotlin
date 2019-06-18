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

package com.virgilsecurity.ratchet.exception

class Exceptions(message: String?) : Exception(message)

/**
 * Exception that is thrown when Ratchet service answers with some error.
 */
class ProtocolException @JvmOverloads constructor(
    val errorCode: Int = -1,
    message: String? = "Unknown error"
) : Exception(message)

class KeyStorageException @JvmOverloads constructor(
    val errorCode: Int = -1,
    message: String? = "Unknown error"
) : Exception(message) {
    companion object {
        val KEY_ALREADY_EXISTS = 1
        val KEY_NOT_FOUND = 2
        val KEY_ALREADY_MARKED = 3
        val ILLEGAL_STORAGE_STATE = 10000
    }
}

class SecureGroupSessionException @JvmOverloads constructor(
    val errorCode: Int = -1,
    message: String? = "Unknown error"
) : Exception(message) {
    companion object {
        val NOT_CONSEQUENT_TICKET = 2
        val INVALID_MESSAGE_TYPE = 3
        val INVALID_CARD_ID = 4
        val PUBLIC_KEY_IS_NOT_VIRGIL = 5
        val WRONG_SENDER = 6
//        val WRONG_MESSAGE_TYPE = 1
//        val WRONG_TICKET_TYPE = 2
//        val CREATE_TICKET = 3
//        val CHANGE_MEMBERS = 4
//        val KEY_TYPE_NOT_SUPPORTED = 5
    }
}

class SecureChatException @JvmOverloads constructor(
    val errorCode: Int = -1,
    message: String? = "Unknown error"
) : Exception(message) {
    companion object {
        val SESSION_ALREADY_EXISTS = 1
        val WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO = 2
        val IDENTITY_KEY_DOESNT_MATCH = 3
        val INVALID_LONG_TERM_KEY_SIGNATURE = 4
        val INVALID_MESSAGE_TYPE = 5
        val INVALID_KEY_TYPE = 6
        val PUBLIC_KEY_SETS_MISMATCH = 7
        val INVALID_SESSION_ID_LENGTH = 8
        val INVALID_CARD_ID = 9
    }
}

class HexEncodingException(message: String? = "Hex encoding failed"): Exception(message) {}