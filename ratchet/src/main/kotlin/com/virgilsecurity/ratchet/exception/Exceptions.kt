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

package com.virgilsecurity.ratchet.exception

/**
 * Exception that is thrown when Ratchet service answers with some error.
 */
class ProtocolException @JvmOverloads constructor(
        val errorCode: Int = -1,
        message: String? = "Unknown error"
) : Exception(message)

/**
 * Exception that is thrown when some errors occur while working with *KeyStorage*.
 */
class KeyStorageException @JvmOverloads constructor(
        val errorCode: Int = -1,
        message: String? = "Unknown error"
) : Exception(message) {
    companion object {
        const val KEY_ALREADY_EXISTS = 1
        const val KEY_NOT_FOUND = 2
        const val KEY_ALREADY_MARKED = 3
        const val ILLEGAL_STORAGE_STATE = 10000
    }
}

/**
 * Exception that is thrown when some error occurs while working with *SecureGroupSession*.
 */
class SecureGroupSessionException @JvmOverloads constructor(
        val errorCode: Int = -1,
        message: String? = when (errorCode) {
            NOT_CONSEQUENT_TICKET -> "Consequent tickets should be passed to updateMembers"
            INVALID_MESSAGE_TYPE -> "Invalid message type"
            INVALID_CARD_ID -> "Invalid card id"
            PUBLIC_KEY_IS_NOT_VIRGIL -> "Public key is not VirgilPublicKey"
            else -> "Unknown error"
        }
) : Exception(message) {
    companion object {
        const val NOT_CONSEQUENT_TICKET = 2
        const val INVALID_MESSAGE_TYPE = 3
        const val INVALID_CARD_ID = 4
        const val PUBLIC_KEY_IS_NOT_VIRGIL = 5
    }
}

/**
 * Exception that is thrown when some error occurs while working with *SecureChat*.
 */
class SecureChatException @JvmOverloads constructor(
        val errorCode: Int = -1,
        message: String? = when(errorCode) {
            SESSION_ALREADY_EXISTS -> "Session with this participant already exists"
            WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO -> "PublicKey is not VirgilPublicKey"
            IDENTITY_KEY_DOESNT_MATCH -> "Identity key in the Card and on Ratchet Cloud doesn't match"
            INVALID_LONG_TERM_KEY_SIGNATURE -> "Long-term key signature is invalid"
            INVALID_MESSAGE_TYPE -> "Message type should be .prekey"
            INVALID_KEY_TYPE -> "Invalid key type"
            PUBLIC_KEY_SETS_MISMATCH -> "PublicKeysSets mismatch"
            INVALID_SESSION_ID_LENGTH -> "Session Id should be 32-byte"
            INVALID_CARD_ID -> "Invalid card id"
            SESSION_ID_MISMATCH -> "Session id mismatch"
            else -> "Unknown error"}
) : Exception(message) {
    companion object {
        const val SESSION_ALREADY_EXISTS = 1
        const val WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO = 2
        const val IDENTITY_KEY_DOESNT_MATCH = 3
        const val INVALID_LONG_TERM_KEY_SIGNATURE = 4
        const val INVALID_MESSAGE_TYPE = 5
        const val INVALID_KEY_TYPE = 6
        const val PUBLIC_KEY_SETS_MISMATCH = 7
        const val INVALID_SESSION_ID_LENGTH = 8
        const val INVALID_CARD_ID = 9
        const val SESSION_ID_MISMATCH = 10
    }
}

/**
 * Exception that is thrown when Hex encoding is failed.
 */
class HexEncodingException(message: String? = "Hex encoding failed") : Exception(message)

class FileDeletionException(
        message: String? = "File deletion failed",
        throwable: Throwable? = null
) : Exception(message, throwable)
