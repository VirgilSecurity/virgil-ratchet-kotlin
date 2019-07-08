# Virgil Security Ratchet Java/Kotlin SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-ratchet-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-ratchet-kotlin)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Register Users](#register-users) | [Chat Example](#chat-example) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>
[Virgil Security](https://virgilsecurity.com) provides a set of services and open source libraries for adding security to any application. If you're developing a chat application, you'll understand the need for a  high level of data protection to ensure confidentiality and data integrity.

You may have heard of our [e3kit](https://github.com/VirgilSecurity/virgil-e3kit-x) which offers a high level of end-to-end encription, but if you need maximum protection with your application, Virgil Security presents the Double Ratchet SDK – an implementation of the [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/). With the powerful tools in this SDK, you can protect encrypted data, even if user messages or a private key has been stolen. The Double Ratchet SDK not only assigns a private encryption key with each chat session, but also allows the developer to limit the lifecycle of these keys. In the event an active key is stolen, it will expire according to the predetermined lifecycle you had set in your application.  

Ratchet SDK interacts with the [PFS service](https://developer.virgilsecurity.com/docs/api-reference/pfs-service/v5) to publish and manage one-time keys (OTK), long-term keys (LTK), and interacts with Virgil Cards service to retrieve the user identity cards the OTK and LTK are based on. The Ratchet SDK issues chat participants new keys for every chat session. As a result new session keys cannot be used to compromise past session keys.

# SDK Features
- communicate with Virgil PFS Service
- manage users' one-time keys (OTK) and long-term keys (LTK)
- enable group or peer-to-peer chat encryption
- uses the [Virgil crypto library](https://github.com/VirgilSecurity/virgil-crypto-c) and [Virgil Core SDK](https://github.com/VirgilSecurity/virgil-sdk-java-android)

## Installation

You can easily add Ratchet SDK dependency to your project with:

### Maven

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity</groupId>
        <artifactId>ratchet</artifactId>
        <version><latest-version></version>
    </dependency>
</dependencies>
```

### Gradle

Add `jcenter()` repository if missing, then update gradle dependencies:

```
    implementation "com.virgilsecurity:ratchet:<latest-version>"
```

The **\<latest-version>** of the Ratchet SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/ratchet)  or in the header of current readme.

## Register Users

Make sure you have registered with the [Virgil Dashboard][_dashboard] and have created an E2EE V5 application.

Besides registering on your own server, users must also be registered on the Virgil Cloud. If they already are, you can skip this step and proceed to the next one.

Every Virgil user has a `Virgil Card` with an unlimited life-time on their device. The card contains a `Private Key`, `Public Key`, and the user's `identity`.

To register users on the Virgil Cloud (i.e. create and publish their `Identity Cards`), follow these steps:
- Set up your backend to generate a JWT to provide your service and users with access to the Virgil Cloud.
- Set up the client side for authenticating users on the Virgil Cloud.
- Set up the Cards Manager on your client side to generate and publish `Virgil Card` with Virgil Cards Service.

If you've already installed the Virgil Ratchet SDK or don't need to install the Virgil SDK or Virgil Crypto, you can use [this guide](https://developer.virgilsecurity.com/docs/how-to/public-key-management/v5/create-card) for the steps described above.

### Initialize SDK

To begin communicating with the PFS service and establish a secure session, each user must run the initialization. To do that, you need the Receiver's public key (identity card) from Virgil Cloud and the sender's private key from their local storage:

```kotlin
val rotateKeysListener = object : OnResultListener<RotationLog> {
    override fun onSuccess(result: RotationLog) {
        // Keys were rotated
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
}

val context = SecureChatContext(identity = card.identity,
                                identityCard = card,
                                identityKeyPair = keyPair,
                                accessTokenProvider = provider)

val secureChat = SecureChat(context = context)

secureChat.rotateKeys().addCallback(rotateKeysListener)
```

During the initialization process, using Identity Cards and the `rotateKeys` method we generate special keys that have their own life-time:

* **One-time Key (OTK)** - each time chat participants want to create a session, a single one-time key is obtained and discarded from the server.
* **Long-term Key (LTK)** - rotated periodically based on the developer's security considerations and is signed with the Identity Private Key.

## Peer-to-peer Chat Example
In this section you'll find out how to build a peer-to-peer chat using the Virgil Ratchet SDK.

### Send initial encrypted message
Let's assume Alice wants to start communicating with Bob and wants to send the first message:
- first, Alice has to create a new chat session by running the `startNewSessionAsSender` function and specify Bob's Identity Card
- then, Alice encrypts the initial message using the `encrypt` SDK function
- finally, The Ratchet SDK doesn't store and update sessions itself. Alice has to store the generated session locally with the `storeSession` SDK function.

```kotlin
// prepare a message
val messageToEncrypt = "Hello, Bob!"

val startNewSessionAsSenderListener = object : OnResultListener<SecureSession> {
    override fun onSuccess(session: SecureSession) {
        val ratchetMessage = session.encrypt(messageToEncrypt)
        secureChat.storeSession(session)
        val encryptedMessage ratchetMessage.serialize()
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
}

// start new secure session with Bob
secureChat.startNewSessionAsSender(receiverCard = bobCard).addCallback(startNewSessionAsSenderListener)
```

**Important**: You need to store the session after operations that change the session's state (encrypt, decrypt), therefore if the session already exists in storage, it will be overwritten

### Decrypt the initial message

After Alice generates and stores the chat session, Bob also has to:
- start the chat session by running the `startNewSessionAsReceiver` function
- decrypt the encrypted message using the `decrypt` SDK function

```kotlin
val ratchetMessage = RatchetMessage.deserialize(encryptedMessage)

val secureSession = secureChat.startNewSessionAsReceiver(senderCard = aliceCard, ratchetMessage = ratchetMessage)

val decryptedMessage = secureSession.decryptString(ratchetMessage)

secureChat.storeSession(session)
```

**Important**: You need to store sessions after operations that change the session's state (encrypt, decrypt). If the session already exists in storage, it will be overwritten

### Encrypt and decrypt messages

#### Encrypting messages
To encrypt future messages, use the `encrypt` function. This function allows you to encrypt data and strings.

> You also need to use message serialization to transfer encrypted messages between users. And do not forget to update sessions in storage as their state changes with every encryption operation!

- Use the following code-snippets to encrypt strings:

```kotlin
val session = secureChat.existingSession(participantIdentity = bobCard.identity)

val message = session.encrypt("Hello, Bob!")

secureChat.storeSession(session)

val messageData = message.serialize()
// Send messageData to Bob
```

- Use the following code-snippets to encrypt data:

```kotlin
val session = secureChat.existingSession(participantIdentity = bobCard.identity)

val message = session.encrypt(data)

secureChat.storeSession(session)

val messageData = message.serialize()
// Send messageData to Bob
```

#### Decrypting Messages
To decrypt messages, use the `decrypt` function. This function allows you to decrypt data and strings.

> You also need to use message serialization to transfer encrypted messages between users. And do not forget to update sessions in storage as their state changes with every decryption operation!

- Use the following code-snippets to decrypt strings:

```kotlin
val session = secureChat.existingSession(participantIdentity = aliceCard.identity)

val ratchetMessage = RatchetMessage.deserialize(messageData)

val decryptedMessage = session.decryptString(ratchetMessage)

secureChat.storeSession(session)
```
- Use the following code-snippets to decrypt data:

```kotlin
val session = secureChat.existingSession(participantIdentity = aliceCard.identity)

val ratchetMessage = RatchetMessage.deserialize(messageData)

val decryptedMessage = session.decryptData(ratchetMessage)

secureChat.storeSession(session)
```


## Group Chat Example
In this section, you'll find out how to build a group chat using the Virgil Ratchet SDK.

### Create Group Chat Ticket
Let's assume Alice wants to start a group chat with Bob and Carol. First, create a new group session ticket by running the `startNewGroupSession` method. This ticket holds a shared root key for future group encryption. Therefore, it should be encrypted and then transmitted to other group participants. Every group chat should have a unique 32-byte session identifier. We recommend tying this identifier to your unique transport channel id. If your channel id is not 32-bytes you can use SHA-256 to derive a session id from it.

```kotlin
// Create transport channel according to your app logic and get session id from it
val sessionId = ConvertionUtils.hexToBytes("7f4f96cedbbd192ddeb08fbf3a0f5db0da14310c287f630a551364c54864c7fb")

val ticket = secureChat.startNewGroupSession(sessionId)
```

### Start Group Chat Session
Now, start the group session by running the `startGroupSession` function. This function requires specifying the group chat session ID, the receivers' Virgil Cards and tickets.

```kotlin
val receiverCards = cardManager.searchCards(listOf("Bob", "Carol"))

val groupSession = secureChat.startGroupSession(receiverCards, sessionId, ticket)
```

###  Store the Group Session
The Ratchet SDK doesn't store and update the group chat session itself. Use the `storeGroupSession` SDK function to store the chat sessions.

> Also, store existing session after operations that change the session's state (encrypt, decrypt, setParticipants, updateParticipants). If the session already exists in storage, it will be overwritten

```kotlin
secureChat.storeGroupSession(groupSession)
```

### Send the Group Ticket
Next, provide the group chat ticket to other members.

- First, serialize the ticket

```kotlin
val ticketData = ticket.serialize()
```

- For security reasons, we can't send the unprotected ticket because it contains an unencrypted symmetric key. Therefore, we have to encrypt the serialized ticket for the receivers. The only secure way to do this is to use peer-to-peer Double Ratchet sessions with each participant to send the ticket.

```kotlin
receiverCards.forEach { card ->
    val session = secureChat.existingSession(participantIdentity = card.identity) ?:
    // If you don't have session, see Peer-to-peer Chat Example on how to create it as Sender.
    return


    val encryptedTicket = session.encrypt(ticketData).serialize()

    secureChat.storeGroupSession(groupSession)

    // Send ticket to receiver
}
```
- Next, use your application's business logic to share the encrypted ticket with the group chat participants.

### Join the Group Chat
Now, when we have the group chat created, other participants can join the chat using the group chat ticket.

- First, we have to decrypt the encrypted ticket

```kotlin
val session = secureChat.existingSession(participantIdentity = "Alice") ?:
// If you don't have a session, see the peer-to-peer chat example on how to create it as a receiver.
return

val encryptedTicketMessage = RatchetMessage.deserialize(encryptedTicket)

val ticketData = session.decryptData(encryptedTicketMessage)
```

- Then, use the `deserialize` function to deserialize the session ticket.

```kotlin
val ticket = RatchetGroupMessage.deserialize(ticketData)
```
- Join the group chat by running the `startGroupSession` function and store the session.

```kotlin
val receiverCards = cardManager.searchCards(listOf("Alice", "Bob"))

val groupSession = secureChat.startGroupSession(receiverCards, sessionId, ticket)

secureChat.storeGroupSession(groupSession)
```

### Encrypt and decrypt messages

#### Encrypting messages
In order to encrypt messages for the group chat, use the `encrypt` function. This function allows you to encrypt data and strings. You still need to use message serialization to transfer encrypted messages between users. And do not forget to update sessions in storage as their state is changed with every encryption operation!

- Use the following code-snippets to encrypt strings:
```kotlin
val message = groupSession.encrypt("Hello, Alice and Bob!")

secureChat.storeGroupSession(groupSession)

val messageData = message.serialize()
// Send messageData to receivers
```

- Use the following code-snippets to encrypt data:
```kotlin
val message = groupSession.encrypt(data)

secureChat.storeGroupSession(groupSession)

val messageData = message.serialize()
// Send messageData to receivers
```

#### Decrypting Messages
To decrypt messages, use the `decrypt` function. This function allows you to decrypt data and strings. Do not forget to update sessions in storage as their state changes with every encryption operation!

- Use the following code-snippets to decrypt strings:
```kotlin
val message = RatchetGroupMessage.deserialize(messageData)

val carolCard = receiversCard.first { it.identity == "Carol" }

val decryptedMessage = groupSession.decryptString(message, senderCardId = carolCard.identifier)

secureChat.storeGroupSession(groupSession)
```
- Use the following code-snippets to decrypt data:
```kotlin
val message = RatchetGroupMessage.deserialize(messageData)

val carolCard = receiversCard.first { it.identity == "Carol" }

val data = groupSession.decryptData(message, senderCardId = carolCard.identifier)

secureChat.storeGroupSession(groupSession)
```


## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information at our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email at support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

[_dashboard]: https://dashboard.virgilsecurity.com/
[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto-c
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_use_cases]: https://developer.virgilsecurity.com/docs/use-cases
[_use_case_pfs]:https://developer.virgilsecurity.com/docs/swift/use-cases/v4/perfect-forward-secrecy

