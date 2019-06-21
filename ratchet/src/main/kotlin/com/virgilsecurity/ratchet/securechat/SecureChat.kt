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
import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.ratchet.client.RatchetClientInterface
import com.virgilsecurity.ratchet.data.SignedPublicKey
import com.virgilsecurity.ratchet.exception.HexEncodingException
import com.virgilsecurity.ratchet.exception.SecureChatException
import com.virgilsecurity.ratchet.keystorage.*
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotatorInterface
import com.virgilsecurity.ratchet.securechat.keysrotation.RotationLog
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.GroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.ratchet.utils.hexStringToByteArray
import com.virgilsecurity.ratchet.utils.logger
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.KeyType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.TokenContext
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

class SecureChat {

    val accessTokenProvider: AccessTokenProvider
    val identityPrivateKey: VirgilPrivateKey
    val crypto: VirgilCrypto
    val longTermKeysStorage: LongTermKeysStorage
    val oneTimeKeysStorage: OneTimeKeysStorage
    val sessionStorage: SessionStorage
    val groupSessionStorage: GroupSessionStorage
    val client: RatchetClientInterface
    val identityCard: Card
    val keyId = RatchetKeyId()
    val keysRotator: KeysRotatorInterface

    /**
     * Create new instance.
     *
     * @param context SecureChatContext
     */
    constructor(context: SecureChatContext) {
        this.crypto = VirgilCrypto()
        this.client = RatchetClient()
        this.accessTokenProvider = context.accessTokenProvider
        this.identityPrivateKey = context.identityKeyPair.privateKey
        this.identityCard = context.identityCard

        this.longTermKeysStorage = FileLongTermKeysStorage(context.identity, this.crypto, context.identityKeyPair)
        this.oneTimeKeysStorage = FileOneTimeKeysStorage(context.identity, this.crypto, context.identityKeyPair)
        this.sessionStorage = FileSessionStorage(context.identity, crypto, context.identityKeyPair)
        this.groupSessionStorage = FileGroupSessionStorage(context.identity, crypto, context.identityKeyPair)
        this.keysRotator = KeysRotator(
                crypto, context.identityKeyPair.privateKey, context.identityCard.identifier,
                context.orphanedOneTimeKeyTtl, context.longTermKeyTtl, context.outdatedLongTermKeyTtl,
                context.desiredNumberOfOneTimeKeys, this.longTermKeysStorage, this.oneTimeKeysStorage,
                this.client
        )
    }

    /**
     * Create new instance.
     *
     * @param crypto VirgilCrypto instance
     * @param identityPrivateKey identity private key
     * @param identityCard identity card
     * @param accessTokenProvider access token provider
     * @param client Ratchet client
     * @param longTermKeysStorage long-term keys storage
     * @param oneTimeKeysStorage one-time keys storage
     * @param sessionStorage session storage
     * @param groupSessionStorage group session storage
     * @param keysRotator keys rotation
     */
    constructor(
            crypto: VirgilCrypto,
            identityPrivateKey: VirgilPrivateKey,
            identityCard: Card,
            accessTokenProvider: AccessTokenProvider,
            client: RatchetClientInterface,
            longTermKeysStorage: LongTermKeysStorage,
            oneTimeKeysStorage: OneTimeKeysStorage,
            sessionStorage: SessionStorage,
            groupSessionStorage: GroupSessionStorage,
            keysRotator: KeysRotatorInterface
    ) {
        this.crypto = crypto
        this.identityPrivateKey = identityPrivateKey
        this.identityCard = identityCard
        this.accessTokenProvider = accessTokenProvider
        this.client = client
        this.longTermKeysStorage = longTermKeysStorage
        this.oneTimeKeysStorage = oneTimeKeysStorage
        this.sessionStorage = sessionStorage
        this.groupSessionStorage = groupSessionStorage
        this.keysRotator = keysRotator
    }

    /**
     * Rotates keys.
     *
     * Rotation process:
     * - Retrieve all one-time keys
     * - Delete one-time keys that were marked as orphaned more than orphanedOneTimeKeyTtl seconds ago
     * - Retrieve all long-term keys
     * - Delete long-term keys that were marked as outdated more than outdatedLongTermKeyTtl seconds ago
     * - Check that all relevant long-term and one-time keys are in the cloud
     * - Mark used one-time keys as used
     * - Decide on long-term key rotation
     * - Generate needed number of one-time keys
     * - Upload keys to the cloud
     *
     * @return RotationLog
     */
    fun rotateKeys(): RotationLog {
        LOG.value.fine("Started keys rotation")

        val tokenContext = TokenContext("rotate", false, "ratchet")
        val token = this.accessTokenProvider.getToken(tokenContext)

        return this.keysRotator.rotateKeys(token)
    }

    /**
     * Stores session.
     * NOTE: This method is used for storing new session as well as updating existing ones after operations that change session's state (encrypt and decrypt), therefore is session already exists in storage, it will be overwritten.
     *
     * @param session session to store
     */
    fun storeSession(session: SecureSession) {
        LOG.value.fine("Storing session with ${session.participantIdentity} name: ${session.name}")

        this.sessionStorage.storeSession(session)
    }

    /**
     * Stores group session.
     * NOTE: This method is used for storing new session as well as updating existing ones after operations that change session's state (encrypt, decrypt, setParticipants, updateParticipants), therefore is session already exists in storage, it will be overwritten.
     *
     * @param session GroupSession to store
     */
    fun storeGroupSession(session: SecureGroupSession) {
        LOG.value.fine("Storing group session with id ${session.identifier().hexEncodedString()}")

        this.groupSessionStorage.storeSession(session)
    }

    /**
     * Checks for existing session with given participent in the storage.
     *
     * @param particpantIdentity participant identity
     * @param name session name
     *
     * @return SecureSession if exists
     */
    fun existingSession(particpantIdentity: String, name: String? = null): SecureSession? {
        val session = this.sessionStorage.retrieveSession(particpantIdentity, name
                ?: SecureChat.DEFAULT_SESSION_NAME)
        if (session != null) {
            LOG.value.fine("Found existing session with $particpantIdentity")
            return session
        } else {
            LOG.value.fine("Existing session with $particpantIdentity was not found")
            return null
        }
    }

    /**
     * Deletes session with given participant identity.
     *
     * @param particpantIdentity participant identity
     * @param name session name
     */
    fun deleteSession(particpantIdentity: String, name: String? = null) {
        LOG.value.fine("Deleting session with $particpantIdentity")

        this.sessionStorage.deleteSession(particpantIdentity, name
                ?: SecureChat.DEFAULT_SESSION_NAME)
    }

    /**
     * Deletes sessions with given participant identity.
     *
     * @param particpantIdentity participant identity
     */
    fun deleteAllSessions(particpantIdentity: String) {
        LOG.value.fine("Deleting session with $particpantIdentity")

        this.sessionStorage.deleteSession(particpantIdentity, null)
    }

    /**
     * Starts new session with given participant using his identity card.
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession()
     *
     * @param receiverCard receiver identity cards
     * @param name session name
     */
    fun startNewSessionAsSender(receiverCard: Card, name: String? = null): SecureSession {
        LOG.value.fine("Starting new session with ${receiverCard.identity}")

        if (this.existingSession(
                        receiverCard.identity,
                        name ?: SecureChat.DEFAULT_SESSION_NAME
                ) != null
        ) {
            throw SecureChatException(SecureChatException.SESSION_ALREADY_EXISTS, "Session is already exists")
        }

        val identityPublicKey = receiverCard.publicKey as? VirgilPublicKey
                ?: throw SecureChatException(
                        SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO,
                        "Public key should be a VirgilPublicKey"
                )

        if (identityPublicKey.keyType != KeyType.ED25519) {
            throw SecureChatException(SecureChatException.INVALID_KEY_TYPE, "Key type should be ED25519")
        }

        val tokenContext = TokenContext("get", false, "ratchet")
        val token = this.accessTokenProvider.getToken(tokenContext)
        val publicKeySet = this.client.getPublicKeySet(receiverCard.identity, token.stringRepresentation())

        val session = this.startNewSessionAsSender(
                receiverCard.identity, identityPublicKey, name,
                publicKeySet.identityPublicKey, publicKeySet.longTermPublicKey, publicKeySet.oneTimePublicKey
        )

        return session
    }

    /**
     * Starts multiple new sessions with given participants using their identity cards.
     * NOTE: This operation doesn't store sessions to storage automatically. Use storeSession()
     *
     * @param receiverCards receivers identity cards
     * @param name session name
     */
    fun startMutipleNewSessionsAsSender(receiverCards: List<Card>, name: String? = null): List<SecureSession> {
        LOG.value.fine("Starting new session with ${receiverCards.map { it.identity }}")

        receiverCards.forEach {
            if (this.existingSession(it.identity, name
                            ?: SecureChat.DEFAULT_SESSION_NAME) != null) {
                throw SecureChatException(
                        SecureChatException.SESSION_ALREADY_EXISTS,
                        "Session with ${it.identity} already exists"
                )
            }
            if (it.publicKey is VirgilPublicKey) {
                val identityPublicKey = it.publicKey as VirgilPublicKey
                if (identityPublicKey.keyType != KeyType.ED25519) {
                    throw SecureChatException(SecureChatException.INVALID_KEY_TYPE, "Public key should be ED25519 type")
                }
            } else {
                throw SecureChatException(
                        SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO,
                        "Public key should be a VirgilPublicKey"
                )
            }
        }

        val tokenContext = TokenContext("get", false, "ratchet")
        val token = this.accessTokenProvider.getToken(tokenContext)
        val publicKeysSets =
                this.client.getMultiplePublicKeysSets(receiverCards.map { it.identity }, token.stringRepresentation())
        if (publicKeysSets.size != receiverCards.size) {
            throw SecureChatException(SecureChatException.PUBLIC_KEY_SETS_MISMATCH, "Wrong public keys count")
        }
        var sessions = mutableListOf<SecureSession>()
        receiverCards.forEach { card ->
            val publicKeySet = publicKeysSets.firstOrNull { it.identity == card.identity }
                    ?: throw SecureChatException(
                            SecureChatException.PUBLIC_KEY_SETS_MISMATCH,
                            "Wrong public keys count"
                    )

            if (card.publicKey !is VirgilPublicKey) {
                throw SecureChatException(SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO, "Wrong card public key")
            }
            val identityPublicKey = card.publicKey as VirgilPublicKey

            val session = this.startNewSessionAsSender(
                    card.identity, identityPublicKey,
                    name, publicKeySet.identityPublicKey, publicKeySet.longTermPublicKey, publicKeySet.oneTimePublicKey
            )

            sessions.add(session)
        }
        return sessions
    }

    private fun startNewSessionAsSender(
            identity: String, identityPublicKey: VirgilPublicKey, name: String?,
            identityPublicKeyData: ByteArray, longTermPublicKey: SignedPublicKey, oneTimePublicKey: ByteArray?
    ): SecureSession {
        if (!this.keyId.computePublicKeyId(identityPublicKeyData)!!.contentEquals(this.keyId.computePublicKeyId(this.crypto.exportPublicKey(identityPublicKey)))) {
            throw SecureChatException(SecureChatException.IDENTITY_KEY_DOESNT_MATCH, "Wrong identity public key")
        }
        if (!this.crypto.verifySignature(longTermPublicKey.signature, longTermPublicKey.publicKey, identityPublicKey)) {
            throw SecureChatException(
                    SecureChatException.INVALID_LONG_TERM_KEY_SIGNATURE,
                    "Long term key signature is invalid"
            )
        }
        if (oneTimePublicKey == null) {
            LOG.value.warning("Creating weak session with $identity")
        }
        val privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey)
        return SecureSession(
                crypto, identity, name ?: DEFAULT_SESSION_NAME,
                privateKeyData, identityPublicKeyData, longTermPublicKey.publicKey, oneTimePublicKey
        )
    }

    private fun replaceOneTimeKey() {
        LOG.value.fine("Adding one time key")
        val oneTimePublicKey: ByteArray

        try {
            this.oneTimeKeysStorage.startInteraction()

            try {
                val keyPair = this.crypto.generateKeyPair(KeyType.CURVE25519)
                val oneTimePrivateKey = this.crypto.exportPrivateKey(keyPair.privateKey)
                oneTimePublicKey = this.crypto.exportPublicKey(keyPair.publicKey)
                val keyId = this.keyId.computePublicKeyId(oneTimePublicKey)

                this.oneTimeKeysStorage.storeKey(oneTimePrivateKey, keyId)

                LOG.value.fine("Saved one-time key successfully")
            } catch (e: Exception) {
                LOG.value.severe("Error saving one-time key")
                return
            }

            try {
                val tokenContext = TokenContext("post", false, "ratchet")
                val token = this.accessTokenProvider.getToken(tokenContext)

                this.client.uploadPublicKeys(
                        null, null, mutableListOf(oneTimePublicKey),
                        token.stringRepresentation()
                )

                LOG.value.fine("Added one-time key successfully")
            } catch (e: Exception) {
                LOG.value.severe("Error adding one-time key")
            }
        } finally {
            this.oneTimeKeysStorage.stopInteraction()
        }
    }

    /**
     * Responds with new session with given participant using his initiation message.
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession()
     *
     * @param senderCard sender identity card
     * @param ratchetMessage Ratchet initiation message (should be PREKEY message)
     *
     * @return SecureSession
     */
    fun startNewSessionAsReceiver(senderCard: Card, ratchetMessage: RatchetMessage): SecureSession {
        return startNewSessionAsReceiver(senderCard, null, ratchetMessage)
    }

    /**
     * Responds with new session with given participant using his initiation message.
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession()
     *
     * @param senderCard sender identity card
     * @param name session name (in case you want to have several sessions with same participant)
     * @param ratchetMessage Ratchet initiation message (should be PREKEY message)
     *
     * @return SecureSession
     */
    fun startNewSessionAsReceiver(senderCard: Card, name: String?, ratchetMessage: RatchetMessage): SecureSession {
        LOG.value.fine("Responding to session with ${senderCard.identity}")

        if (this.existingSession(senderCard.identity, name) != null) {
            throw SecureChatException(
                    SecureChatException.SESSION_ALREADY_EXISTS,
                    "Session already exists"
            )
        }

        if (senderCard.publicKey !is VirgilPublicKey) {
            throw SecureChatException(
                    SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO,
                    "Identity public key should be a VirgilPublicKey"
            )
        }
        val senderIdentityPublicKey = senderCard.publicKey as VirgilPublicKey

        if (senderIdentityPublicKey.keyType != KeyType.ED25519) {
            throw SecureChatException(
                    SecureChatException.INVALID_KEY_TYPE,
                    "Identity public key should be a ED25519 type"
            )
        }

        if (ratchetMessage.type != MsgType.PREKEY) {
            throw SecureChatException(
                    SecureChatException.INVALID_MESSAGE_TYPE,
                    "Ratchet message should be PREKEY type"
            )
        }

        val receiverLongTermPublicKey = ratchetMessage.longTermPublicKey
        val longTermKeyId = this.keyId.computePublicKeyId(receiverLongTermPublicKey)
        val receiverLongTermPrivateKey = this.longTermKeysStorage.retrieveKey(longTermKeyId)
        val receiverOneTimePublicKey = ratchetMessage.oneTimePublicKey

        val receiverOneTimeKeyId: ByteArray?

        if (receiverOneTimePublicKey.isEmpty()) {
            receiverOneTimeKeyId = null
        } else {
            receiverOneTimeKeyId = this.keyId.computePublicKeyId(receiverOneTimePublicKey)
        }
        val receiverOneTimePrivateKey: OneTimeKey?
        var interactionStarted = false
        try {
            if (receiverOneTimeKeyId == null) {
                receiverOneTimePrivateKey = null
            } else {
                this.oneTimeKeysStorage.startInteraction()
                interactionStarted = true
                receiverOneTimePrivateKey = this.oneTimeKeysStorage.retrieveKey(receiverOneTimeKeyId)
            }

            val session = SecureSession(
                    this.crypto,
                    senderCard.identity,
                    name ?: SecureChat.DEFAULT_SESSION_NAME,
                    this.identityPrivateKey,
                    receiverLongTermPrivateKey,
                    receiverOneTimePrivateKey,
                    this.crypto.exportPublicKey(senderIdentityPublicKey),
                    ratchetMessage
            )

            if (receiverOneTimeKeyId != null) {
                this.oneTimeKeysStorage.deleteKey(receiverOneTimeKeyId)
                this.replaceOneTimeKey()
            }
            return session
        } finally {
            if (interactionStarted) {
                this.oneTimeKeysStorage.stopInteraction()
            }
        }
    }

    /**
     * Creates RatchetGroupMessage that starts new group chat.
     * NOTE: Other participants should receive this message using encrypted channel (SecureSession).
     *
     * @param customSessionId optional session Id. Should be 32 byte. If null passed random value will be generated
     *
     * @return RatchetGroupMessage that should be then passed to startGroupSession()
     */
    fun startNewGroupSession(customSessionId: ByteArray? = null): RatchetGroupMessage {
        val ticket = RatchetGroupTicket()
        ticket.setRng(this.crypto.rng)
        ticket.setupTicketAsNew()

        if (customSessionId != null) {
            if (customSessionId.size != RatchetCommon().sessionIdLen) {
                throw SecureChatException(SecureChatException.INVALID_SESSION_ID_LENGTH, "Session ID should be 32 byte length")
            }
            ticket.setSessionId(customSessionId)
        }

        return ticket.ticketMessage
    }

    /**
     * Creates secure group session that was initiated by someone.
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession()
     * RatchetGroupMessage should be of GROUP_INFO type. Such messages should be sent encrypted (using SecureSession)
     *
     * @param receiversCards participant cards (excluding creating user itself)
     * @param ratchetMessage ratchet group message of GROUP_INFO type
     *
     * @return SecureGroupSession
     */
    fun startGroupSession(receiversCards: List<Card>, ratchetMessage: RatchetGroupMessage): SecureGroupSession {
        if (ratchetMessage.type != GroupMsgType.GROUP_INFO) {
            throw SecureChatException(
                    SecureChatException.INVALID_MESSAGE_TYPE,
                    "Ratchet message should be GROUP_INFO type"
            )
        }

        val privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey)

        try {
            val myId = this.identityCard.identifier.hexStringToByteArray()

            return SecureGroupSession(this.crypto, privateKeyData, myId,
                    ratchetMessage,
                    receiversCards)
        } catch (e: HexEncodingException) {
            throw SecureChatException(
                    SecureChatException.INVALID_CARD_ID,
                    "Card ID is not HEX encoded"
            )
        }
    }

    /**
     * Returns existing group session.
     *
     * @param sessionId session identifier
     *
     * @return stored session if found, null otherwise
     */
    fun existingGroupSession(sessionId: ByteArray): SecureGroupSession? {
        val identifier = sessionId.hexEncodedString()
        val session = this.groupSessionStorage.retrieveSession(sessionId)
        if (session == null) {
            LOG.value.fine("Existing session with identifier: $identifier was not found")
        } else {
            LOG.value.fine("Found existing group session with identifier: $identifier")
        }

        return session
    }

    /**
     * Removes all data corresponding to this user: sessions and keys.
     */
    fun reset() {
        LOG.value.fine("Reset secure chat")

        val tokenContext = TokenContext("delete", false, "ratchet")
        val token = this.accessTokenProvider.getToken(tokenContext)

        LOG.value.fine("Resetting cloud")
        this.client.deleteKeysEntity(token.stringRepresentation())

        LOG.value.fine("Resetting one-time keys")
        this.oneTimeKeysStorage.reset()

        LOG.value.fine("Resetting long-term keys")
        this.longTermKeysStorage.reset()

        LOG.value.fine("Resetting sessions")
        this.sessionStorage.reset()

        LOG.value.fine("Resetting success")
    }

    companion object {
        /**
         * Default session name.
         */
        val DEFAULT_SESSION_NAME = "DEFAULT"
        val LOG = logger()
    }
}