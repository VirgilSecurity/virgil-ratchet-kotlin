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

package com.virgilsecurity.ratchet.securechat

import com.virgilsecurity.crypto.ratchet.*
import com.virgilsecurity.ratchet.exception.SecureGroupSessionException
import com.virgilsecurity.ratchet.sessionstorage.GroupSessionStorage
import com.virgilsecurity.ratchet.utils.areEquals
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.ratchet.utils.hexStringToByteArray
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import java.nio.charset.StandardCharsets

class SecureGroupSession {

    val crypto: VirgilCrypto
    val sessionStorage: GroupSessionStorage
    val ratchetGroupSession: RatchetGroupSession
    val syncObj = 1

    constructor(
        crypto: VirgilCrypto,
        sessionStorage: GroupSessionStorage,
        privateKeyData: ByteArray,
        myId: ByteArray,
        ratchetGroupMessage: RatchetGroupMessage
    ) {
        this.crypto = crypto
        this.sessionStorage = sessionStorage

        this.ratchetGroupSession = RatchetGroupSession()
        this.ratchetGroupSession.setRng(crypto.rng)
        this.ratchetGroupSession.setPrivateKey(privateKeyData)
        this.ratchetGroupSession.myId = myId
        this.ratchetGroupSession.setupSession(ratchetGroupMessage)
    }

    constructor(data: ByteArray, privateKeyData: ByteArray, sessionStorage: GroupSessionStorage, crypto: VirgilCrypto) {
        this.crypto = crypto
        this.sessionStorage = sessionStorage

        this.ratchetGroupSession = RatchetGroupSession.deserialize(data)
        this.ratchetGroupSession.setRng(crypto.rng)
        this.ratchetGroupSession.setPrivateKey(privateKeyData)
    }

    fun identifier(): String {
        return this.ratchetGroupSession.sessionId.hexEncodedString()
    }

    fun myIdentifier(): String {
        return this.ratchetGroupSession.myId.hexEncodedString()
    }

    fun participantsCount(): Int {
        return this.ratchetGroupSession.participantsCount
    }

    /**
     * Encrypts string. Updates session in storage.
     *
     * @param string message to encrypt
     * @return RatchetMessage
     */
    fun encrypt(string: String): RatchetGroupMessage {
        val data = string.toByteArray(StandardCharsets.UTF_8)
        return this.encrypt(data)
    }

    /**
     * Encrypts data. Updates session in storage.
     *
     * @param data message to encrypt
     * @return RatchetMessage
     */
    fun encrypt(data: ByteArray): RatchetGroupMessage {
        synchronized(syncObj) {
            val msg = this.ratchetGroupSession.encrypt(data)
            this.sessionStorage.storeSession(this)
            return msg
        }
    }

    /**
     * Decrypts data from RatchetMessage. Updates session in storage.
     *
     * @param message RatchetGroupMessage
     * @return Decrypted data
     */
    fun decryptData(message: RatchetGroupMessage): ByteArray {
        synchronized(syncObj) {
            val data = this.ratchetGroupSession.decrypt(message)
            this.sessionStorage.storeSession(this)
            return data
        }
    }

    /**
     * Decrypts utf-8 string from RatchetMessage. Updates session in storage.
     *
     * @param message RatchetGroupMessage
     * @return Decrypted utf-8 string
     */
    fun decryptString(message: RatchetGroupMessage): String {
        if (message.type != GroupMsgType.REGULAR) {
            throw SecureGroupSessionException(
                SecureGroupSessionException.WRONG_MESSAGE_TYPE,
                "Group message should be REGULAR"
            )
        }

        val data = this.decryptData(message)
        return data.toString(StandardCharsets.UTF_8)
    }

    fun createChangeMembersTicket(addCards: List<Card>, removeCardIds: List<String>): RatchetGroupMessage {
        if (addCards.isEmpty() && removeCardIds.isEmpty()) {
            throw SecureGroupSessionException(SecureGroupSessionException.CREATE_TICKET, "No cards to change set")
        }

        val ticket = if (addCards.isNotEmpty()) {
            this.ratchetGroupSession.createGroupTicketForAddingParticipants()
        } else {
            this.ratchetGroupSession.createGroupTicketForAddingOrRemovingParticipants()
        }

        removeCardIds.forEach {
            val idData = it.hexStringToByteArray()
            ticket.removeParticipant(idData)
        }

        addCards.forEach {
            val participantId = it.identifier.hexStringToByteArray()

            val publicKey = if (it.publicKey is VirgilPublicKey) {
                it.publicKey as VirgilPublicKey
            } else {
                throw SecureGroupSessionException(
                    SecureGroupSessionException.KEY_TYPE_NOT_SUPPORTED,
                    "Only VirgilPublicKey supported"
                )
            }

            val publicKeyData = this.crypto.exportPublicKey(publicKey)
            ticket.addNewParticipant(participantId, publicKeyData)
        }
        return ticket.ticketMessage
    }

    fun useChangeMembersTicket(ticket: RatchetGroupMessage, addCards: List<Card>, removeCardIds: List<String>) {
        if (ticket.type != GroupMsgType.GROUP_INFO) {
            throw SecureGroupSessionException(
                SecureGroupSessionException.WRONG_TICKET_TYPE,
                "Ticket type should be GROUP_INFO"
            )
        }
        if (addCards.isEmpty() && removeCardIds.isEmpty()) {
            throw SecureGroupSessionException(SecureGroupSessionException.CHANGE_MEMBERS, "No cards to change set")
        }

        if (ticket.pubKeyCount - 1 != this.participantsCount() + addCards.size - removeCardIds.size) {
            throw SecureGroupSessionException(SecureGroupSessionException.CHANGE_MEMBERS, "Invalid cards count")
        }

        val keyId = RatchetKeyId()

        addCards.forEach {
            val participantId = it.identifier.hexStringToByteArray()
            val publicKey = if (it.publicKey is VirgilPublicKey) {
                it.publicKey as VirgilPublicKey
            } else {
                throw SecureGroupSessionException(
                    SecureGroupSessionException.KEY_TYPE_NOT_SUPPORTED,
                    "Only VirgilPublicKey supported"
                )
            }

            val publicKeyData = this.crypto.exportPublicKey(publicKey)
            val cardPublicKeyId = keyId.computePublicKeyId(publicKeyData)
            val msgPublicKeyId = ticket.getPubKeyId(participantId)

            if (areEquals(msgPublicKeyId, cardPublicKeyId)) {
                throw SecureGroupSessionException(
                    SecureGroupSessionException.CHANGE_MEMBERS,
                    "Wrong ticket public key"
                )
            }
        }

        removeCardIds.forEach {
            val idData = it.hexStringToByteArray()
            var pubKetIdIsAbsent = false
            try {
                ticket.getPubKeyId(idData)
            } catch (e: RatchetException) {
                pubKetIdIsAbsent = true
            }

            if (!pubKetIdIsAbsent) {
                throw SecureGroupSessionException(
                    SecureGroupSessionException.CHANGE_MEMBERS,
                    "User doesn't present in a group message"
                )
            }
        }

        this.ratchetGroupSession.setupSession(ticket)
    }

    /**
     * Serialize session.
     */
    fun serialize(): ByteArray {
        return this.ratchetGroupSession.serialize()
    }
}