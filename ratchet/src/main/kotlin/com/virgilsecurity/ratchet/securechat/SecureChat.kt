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

package com.virgilsecurity.ratchet.securechat

import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.crypto.ratchet.*
import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.ratchet.client.RatchetClientInterface
import com.virgilsecurity.ratchet.client.data.SignedPublicKey
import com.virgilsecurity.ratchet.exception.HexEncodingException
import com.virgilsecurity.ratchet.exception.SecureChatException
import com.virgilsecurity.ratchet.keystorage.*
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotator
import com.virgilsecurity.ratchet.securechat.keysrotation.KeysRotatorInterface
import com.virgilsecurity.ratchet.securechat.keysrotation.RotationLog
import com.virgilsecurity.ratchet.sessionstorage.FileGroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.FileSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.GroupSessionStorage
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import com.virgilsecurity.ratchet.utils.hexEncodedString
import com.virgilsecurity.ratchet.utils.hexStringToByteArray
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.TokenContext
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import java.util.logging.Logger

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
     * @param context Contains info required to instantiate [SecureChat] object.
     */
    constructor(context: SecureChatContext) {
        this.crypto = context.virgilCrypto
        this.client = context.ratchetClient
        this.accessTokenProvider = context.accessTokenProvider
        this.identityPrivateKey = context.identityKeyPair.privateKey
        this.identityCard = context.identityCard

        this.longTermKeysStorage =
                FileLongTermKeysStorage(context.identityCard.identity, this.crypto, context.identityKeyPair, context.rootPath)
        this.oneTimeKeysStorage =
                FileOneTimeKeysStorage(context.identityCard.identity, this.crypto, context.identityKeyPair, context.rootPath)
        this.sessionStorage =
                FileSessionStorage(context.identityCard.identity, crypto, context.identityKeyPair, context.rootPath)
        this.groupSessionStorage =
                FileGroupSessionStorage(context.identityCard.identity, crypto, context.identityKeyPair, context.rootPath)
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
     * @param crypto VirgilCrypto instance.
     * @param identityPrivateKey Identity private key.
     * @param identityCard Identity card.
     * @param accessTokenProvider Access token provider.
     * @param client Ratchet client.
     * @param longTermKeysStorage Long-term keys storage.
     * @param oneTimeKeysStorage One-time keys storage.
     * @param sessionStorage Session storage.
     * @param groupSessionStorage Group session storage.
     * @param keysRotator Keys rotation
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
     * @return RotationLog.
     */
    fun rotateKeys() = object : Result<RotationLog> {
        override fun get(): RotationLog {
            logger.fine("Started keys rotation")

            val tokenContext = TokenContext(SERVICE, OPERATION_ROTATE)
            val token = this@SecureChat.accessTokenProvider.getToken(tokenContext)

            return this@SecureChat.keysRotator.rotateKeys(token).get()
        }
    }

    /**
     * Stores session.
     * NOTE: This method is used for storing new session as well as updating existing ones after operations that
     * change session's state (encrypt and decrypt), therefore is session already exists in storage, it will
     * be overwritten.
     *
     * @param session Session to store.
     */
    fun storeSession(session: SecureSession) {
        logger.fine("Storing session with ${session.participantIdentity} name: ${session.name}")

        this.sessionStorage.storeSession(session)
    }

    /**
     * Stores group session.
     *
     * NOTE: This method is used for storing new session as well as updating existing ones after operations that
     * change session's state (encrypt, decrypt, setParticipants, updateParticipants), therefore is session already
     * exists in storage, it will be overwritten.
     *
     * @param session GroupSession to store.
     */
    fun storeGroupSession(session: SecureGroupSession) {
        logger.fine("Storing group session with id ${session.identifier().hexEncodedString()}")

        this.groupSessionStorage.storeSession(session)
    }

    /**
     * Checks for existing session with given participant in the storage.
     *
     * @param participantIdentity Participant identity.
     * @param name Session name.
     *
     * @return SecureSession if exists.
     */
    fun existingSession(participantIdentity: String, name: String? = null): SecureSession? {
        val session = this.sessionStorage.retrieveSession(participantIdentity, name ?: OPERATION_DEFAULT_SESSION_NAME)
        return if (session != null) {
            logger.fine("Found existing session with $participantIdentity")
            session
        } else {
            logger.fine("Existing session with $participantIdentity was not found")
            null
        }
    }

    /**
     * Deletes session with given participant identity.
     *
     * @param participantIdentity Participant identity.
     * @param name Session name.
     */
    fun deleteSession(participantIdentity: String, name: String? = null) {
        logger.fine("Deleting session with $participantIdentity")

        this.sessionStorage.deleteSession(participantIdentity, name ?: OPERATION_DEFAULT_SESSION_NAME)
    }

    /**
     * Deletes sessions with given participant identity.
     *
     * @param participantIdentity Participant identity.
     */
    fun deleteAllSessions(participantIdentity: String) {
        logger.fine("Deleting session with $participantIdentity")

        this.sessionStorage.deleteSession(participantIdentity, null)
    }

    /**
     * Deletes group session with given identifier.
     *
     * @param sessionId Session identifier.
     */
    fun deleteGroupSession(sessionId: ByteArray) {
        logger.fine("Deleting group session with ${sessionId.hexEncodedString()}")
        this.groupSessionStorage.deleteSession(sessionId)
    }

    /**
     * Starts new session with given participant using his identity card.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     *
     * @param receiverCard Receiver identity cards.
     * @param name Session name.
     */
    fun startNewSessionAsSender(receiverCard: Card, name: String? = null) = object : Result<SecureSession> {
        override fun get(): SecureSession {
            logger.fine("Starting new session with ${receiverCard.identity}")

            if (existingSession(receiverCard.identity, name ?: OPERATION_DEFAULT_SESSION_NAME) != null) {
                throw SecureChatException(SecureChatException.SESSION_ALREADY_EXISTS, "Session is already exists")
            }

            val identityPublicKey = receiverCard.publicKey
                    ?: throw SecureChatException(
                            SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO,
                            "Public key should be a VirgilPublicKey"
                    )

            if (identityPublicKey.keyPairType != KeyPairType.ED25519) {
                throw SecureChatException(SecureChatException.INVALID_KEY_TYPE, "Key type should be ED25519")
            }

            val tokenContext = TokenContext(SERVICE, OPERATION_START_NEW_SESSION_AS_SENDER)
            val token = this@SecureChat.accessTokenProvider.getToken(tokenContext)
            val publicKeySet = this@SecureChat.client.getPublicKeySet(receiverCard.identity,
                                                                      token.stringRepresentation()).get()

            return startNewSessionAsSender(
                    receiverCard.identity, identityPublicKey, name,
                    publicKeySet.identityPublicKey, publicKeySet.longTermPublicKey, publicKeySet.oneTimePublicKey
            )
        }
    }

    /**
     * Starts multiple new sessions with given participants using their identity cards.
     *
     * NOTE: This operation doesn't store sessions to storage automatically. Use storeSession().
     *
     * @param receiverCards Receivers identity cards.
     * @param name Session name.
     */
    fun startMutipleNewSessionsAsSender(receiverCards: List<Card>,
                                        name: String? = null) = object : Result<List<SecureSession>> {
        override fun get(): List<SecureSession> {
            logger.fine("Starting new session with ${receiverCards.map { it.identity }}")

            receiverCards.forEach {
                if (existingSession(it.identity, name ?: OPERATION_DEFAULT_SESSION_NAME) != null) {
                    throw SecureChatException(
                            SecureChatException.SESSION_ALREADY_EXISTS,
                            "Session with ${it.identity} already exists"
                    )
                }
                if (it.publicKey is VirgilPublicKey) {
                    val identityPublicKey = it.publicKey as VirgilPublicKey
                    if (identityPublicKey.keyPairType != KeyPairType.ED25519) {
                        throw SecureChatException(SecureChatException.INVALID_KEY_TYPE,
                                                  "Public key should be ED25519 type")
                    }
                } else {
                    throw SecureChatException(
                            SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO,
                            "Public key should be a VirgilPublicKey"
                    )
                }
            }

            val tokenContext = TokenContext(SERVICE, OPERATION_START_MULTIPLE_NEW_SESSIONS_AS_SENDER)
            val token = this@SecureChat.accessTokenProvider.getToken(tokenContext)
            val publicKeysSets =
                    this@SecureChat.client.getMultiplePublicKeysSets(receiverCards.map { it.identity },
                                                                     token.stringRepresentation()).get()
            if (publicKeysSets.size != receiverCards.size) {
                throw SecureChatException(SecureChatException.PUBLIC_KEY_SETS_MISMATCH, "Wrong public keys count")
            }
            val sessions = mutableListOf<SecureSession>()
            receiverCards.forEach { card ->
                val publicKeySet = publicKeysSets.firstOrNull { it.identity == card.identity }
                        ?: throw SecureChatException(
                                SecureChatException.PUBLIC_KEY_SETS_MISMATCH,
                                "Wrong public keys count"
                        )

                if (card.publicKey !is VirgilPublicKey) {
                    throw SecureChatException(SecureChatException.WRONG_IDENTIRY_PUBLIC_KEY_CRYPTO,
                                              "Wrong card public key")
                }
                val identityPublicKey = card.publicKey as VirgilPublicKey

                val session = startNewSessionAsSender(
                        card.identity,
                        identityPublicKey,
                        name,
                        publicKeySet.identityPublicKey,
                        publicKeySet.longTermPublicKey,
                        publicKeySet.oneTimePublicKey)

                sessions.add(session)
            }
            return sessions
        }
    }

    private fun startNewSessionAsSender(
            identity: String, identityPublicKey: VirgilPublicKey, name: String?,
            identityPublicKeyData: ByteArray, longTermPublicKey: SignedPublicKey, oneTimePublicKey: ByteArray?
    ): SecureSession {
        if (!this.keyId.computePublicKeyId(identityPublicKeyData)!!.contentEquals(this.keyId.computePublicKeyId(this.crypto.exportPublicKey(identityPublicKey)))) {
            throw SecureChatException(SecureChatException.IDENTITY_KEY_DOESNT_MATCH)
        }
        if (!this.crypto.verifySignature(longTermPublicKey.signature, longTermPublicKey.publicKey, identityPublicKey)) {
            throw SecureChatException(SecureChatException.INVALID_LONG_TERM_KEY_SIGNATURE)
        }
        if (oneTimePublicKey == null) {
            logger.warning("Creating weak session with $identity")
        }
        val privateKeyData = this.crypto.exportPrivateKey(this.identityPrivateKey)
        return SecureSession(
                crypto, identity, name ?: OPERATION_DEFAULT_SESSION_NAME,
                privateKeyData, identityPublicKeyData, longTermPublicKey.publicKey, oneTimePublicKey
        )
    }

    private fun replaceOneTimeKey() = object : Completable {
        override fun execute() {
            logger.fine("Adding one time key")
            val oneTimePublicKey: ByteArray

            try {
                this@SecureChat.oneTimeKeysStorage.startInteraction()

                try {
                    val keyPair = this@SecureChat.crypto.generateKeyPair(KeyPairType.CURVE25519)
                    val oneTimePrivateKey = this@SecureChat.crypto.exportPrivateKey(keyPair.privateKey)
                    oneTimePublicKey = this@SecureChat.crypto.exportPublicKey(keyPair.publicKey)
                    val keyId = this@SecureChat.keyId.computePublicKeyId(oneTimePublicKey)

                    this@SecureChat.oneTimeKeysStorage.storeKey(oneTimePrivateKey, keyId)

                    logger.fine("Saved one-time key successfully")
                } catch (e: Exception) {
                    logger.severe("Error saving one-time key")
                    return
                }

                try {
                    val tokenContext = TokenContext(SERVICE, OPERATION_REPLACE_ONE_TIME_KEY)
                    val token = this@SecureChat.accessTokenProvider.getToken(tokenContext)

                    this@SecureChat.client.uploadPublicKeys(
                            null, null, mutableListOf(oneTimePublicKey),
                            token.stringRepresentation()
                    ).execute()

                    logger.fine("Added one-time key successfully")
                } catch (e: Exception) {
                    logger.severe("Error adding one-time key")
                }
            } finally {
                this@SecureChat.oneTimeKeysStorage.stopInteraction()
            }
        }
    }

    /**
     * Responds with new session with given participant using his initiation message.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     *
     * @param senderCard Sender identity card.
     * @param ratchetMessage Ratchet initiation message (should be PREKEY message).
     *
     * @return SecureSession.
     */
    fun startNewSessionAsReceiver(senderCard: Card, ratchetMessage: RatchetMessage): SecureSession {
        return startNewSessionAsReceiver(senderCard, null, ratchetMessage)
    }

    /**
     * Responds with new session with given participant using his initiation message.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     *
     * @param senderCard Sender identity card.
     * @param name Session name (in case you want to have several sessions with same participant).
     * @param ratchetMessage Ratchet initiation message (should be PREKEY message).
     *
     * @return SecureSession.
     */
    fun startNewSessionAsReceiver(senderCard: Card, name: String?, ratchetMessage: RatchetMessage): SecureSession {
        logger.fine("Responding to session with ${senderCard.identity}")

        if (existingSession(senderCard.identity, name) != null) {
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

        if (senderIdentityPublicKey.keyPairType != KeyPairType.ED25519) {
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

        val receiverOneTimeKeyId = if (receiverOneTimePublicKey.isEmpty()) {
            null
        } else {
            this.keyId.computePublicKeyId(receiverOneTimePublicKey)
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
                    name ?: OPERATION_DEFAULT_SESSION_NAME,
                    this.identityPrivateKey,
                    receiverLongTermPrivateKey,
                    receiverOneTimePrivateKey,
                    this.crypto.exportPublicKey(senderIdentityPublicKey),
                    ratchetMessage
            )

            if (receiverOneTimeKeyId != null) {
                this.oneTimeKeysStorage.deleteKey(receiverOneTimeKeyId)
                replaceOneTimeKey().execute()
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
     *
     * NOTE: Other participants should receive this message using encrypted channel (SecureSession).
     *
     * @param sessionId Session Id. Should be 32 byte.
     *
     * @return RatchetGroupMessage that should be then passed to startGroupSession().
     */
    fun startNewGroupSession(sessionId: ByteArray): RatchetGroupMessage {
        val ticket = RatchetGroupTicket()
        ticket.setRng(this.crypto.rng)

        if (sessionId.size != RatchetCommon().sessionIdLen) {
            throw SecureChatException(SecureChatException.INVALID_SESSION_ID_LENGTH, "Session ID should be 32 byte length")
        }
        ticket.setupTicketAsNew(sessionId)

        return ticket.ticketMessage
    }

    /**
     * Creates secure group session that was initiated by someone.
     *
     * NOTE: This operation doesn't store session to storage automatically. Use storeSession().
     * RatchetGroupMessage should be of GROUP_INFO type. Such messages should be sent encrypted (using SecureSession).
     *
     * @param receiversCards Participant cards (excluding creating user itself).
     * @param sessionId Session Id. Should be 32 byte.
     * @param ratchetMessage Ratchet group message of GROUP_INFO type.
     *
     * @return SecureGroupSession.
     */
    fun startGroupSession(receiversCards: List<Card>, sessionId: ByteArray, ratchetMessage: RatchetGroupMessage): SecureGroupSession {
        if (ratchetMessage.type != GroupMsgType.GROUP_INFO) {
            throw SecureChatException(
                    SecureChatException.INVALID_MESSAGE_TYPE,
                    "Ratchet message should be GROUP_INFO type"
            )
        }

        if (!ratchetMessage.sessionId!!.contentEquals(sessionId)) {
            throw SecureChatException(SecureChatException.SESSION_ID_MISMATCH)
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
     * @param sessionId Session identifier.
     *
     * @return Stored session if found, null otherwise.
     */
    fun existingGroupSession(sessionId: ByteArray): SecureGroupSession? {
        val identifier = sessionId.hexEncodedString()
        val session = this.groupSessionStorage.retrieveSession(sessionId)
        if (session == null) {
            logger.fine("Existing session with identifier: $identifier was not found")
        } else {
            logger.fine("Found existing group session with identifier: $identifier")
        }

        return session
    }

    /**
     * Removes all data corresponding to this user: sessions and keys.
     */
    fun reset() = object : Completable {
        override fun execute() {
            logger.fine("Reset secure chat")

            val tokenContext = TokenContext(SERVICE, OPERATION_RESET)
            val token = this@SecureChat.accessTokenProvider.getToken(tokenContext)

            logger.fine("Resetting cloud")
            this@SecureChat.client.deleteKeysEntity(token.stringRepresentation()).execute()

            logger.fine("Resetting one-time keys")
            this@SecureChat.oneTimeKeysStorage.reset()

            logger.fine("Resetting long-term keys")
            this@SecureChat.longTermKeysStorage.reset()

            logger.fine("Resetting sessions")
            this@SecureChat.sessionStorage.reset()

            logger.fine("Resetting success")
        }
    }

    companion object {
        /**
         * Default session name.
         */
        private const val OPERATION_DEFAULT_SESSION_NAME = "DEFAULT"

        private const val SERVICE = "ratchet"

        private const val OPERATION_START_NEW_SESSION_AS_SENDER = "start_new_session_as_sender"
        private const val OPERATION_START_MULTIPLE_NEW_SESSIONS_AS_SENDER = "start_multiple_new_sessions_as_sender"
        private const val OPERATION_REPLACE_ONE_TIME_KEY = "replace_one_time_key"
        private const val OPERATION_RESET = "reset"
        private const val OPERATION_ROTATE = "rotate"

        private val logger = Logger.getLogger(SecureChat::class.java.name)
    }
}
