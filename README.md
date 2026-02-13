# Virgil Security Ratchet Java/Kotlin SDK

[![Build and Test](https://github.com/VirgilSecurity/virgil-ratchet-kotlin/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/VirgilSecurity/virgil-ratchet-kotlin/actions/workflows/build-and-test.yml)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil-ratchet-kotlin/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Register Users](#register-users) | [Peer-to-peer Chat Example](#peer-to-peer-chat-example) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>
[Virgil Security](https://virgilsecurity.com) provides a set of services and open source libraries for adding security to any application. If you're developing a chat application, you'll understand the need for a  high level of data protection to ensure confidentiality and data integrity.

You may have heard of our [e3kit](https://github.com/VirgilSecurity/virgil-e3kit-x) which offers a high level of end-to-end encryption, but if you need maximum protection with your application, Virgil Security presents the Double Ratchet SDK – an implementation of the [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/). With the powerful tools in this SDK, you can protect encrypted data, even if user messages or a private key has been stolen. The Double Ratchet SDK not only assigns a private encryption key with each chat session, but also allows the developer to limit the lifecycle of these keys. In the event an active key is stolen, it will expire according to the predetermined lifecycle you had set in your application.  

Ratchet SDK interacts with the [PFS service](https://developer.virgilsecurity.com/docs/api-reference/pfs-service/v5) to publish and manage one-time keys (OTK), long-term keys (LTK), and interacts with Virgil Cards service to retrieve the user identity cards the OTK and LTK are based on. The Ratchet SDK issues chat participants new keys for every chat session. As a result new session keys cannot be used to compromise past session keys.

# SDK Features
- communicate with Virgil PFS Service
- manage users' one-time keys (OTK) and long-term keys (LTK)
- enable peer-to-peer chat encryption
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

Add Maven Central repository if missing, then update gradle dependencies:

```
    implementation "com.virgilsecurity:ratchet:<latest-version>"
```

The **\<latest-version>** of the Ratchet SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/ratchet)  or in the header of current readme.

## Compatibility Notes

- Current build is aligned with:
  - `com.virgilsecurity.sdk:virgil-sdk` `7.4.0`
  - `com.virgilsecurity.crypto:ratchet` `0.17.2`
- Key IDs used by the Ratchet service are computed as `SHA-512(raw 32-byte public key)[0..7]` (see `RatchetKeyIdCompat`).
  - Do not assume `VirgilPublicKey.identifier` matches Ratchet/PFS key IDs.
- Group ratchet API was removed upstream in `ratchet 0.17.x`.
  - Peer-to-peer secure sessions are supported.
  - Group chat API is removed from this SDK.

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
val context = SecureChatContext(identityCard = card,
                                identityKeyPair = keyPair,
                                accessTokenProvider = provider)

val secureChat = SecureChat(context = context)

val rotationLog: RotationLog = secureChat.rotateKeys().get()
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

val session: SecureSession = secureChat.startNewSessionAsSender(receiverCard = bobCard).get()

val ratchetMessage = session.encrypt(messageToEncrypt)
secureChat.storeSession(session)

val encryptedMessage = ratchetMessage.serialize()
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

secureChat.storeSession(secureSession)
```

**Important**: You need to store sessions after operations that change the session's state (encrypt, decrypt). If the session already exists in storage, it will be overwritten

### Encrypt and decrypt messages

#### Encrypting messages
To encrypt future messages, use the `encrypt` function. This function allows you to encrypt data and strings.

> You also need to use message serialization to transfer encrypted messages between users. And do not forget to update sessions in storage as their state changes with every encryption operation!

- Use the following code-snippets to encrypt strings:

```kotlin
val session = requireNotNull(secureChat.existingSession(participantIdentity = bobCard.identity))

val message = session.encrypt("Hello, Bob!")

secureChat.storeSession(session)

val messageData = message.serialize()
// Send messageData to Bob
```

- Use the following code-snippets to encrypt data:

```kotlin
val session = requireNotNull(secureChat.existingSession(participantIdentity = bobCard.identity))

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
val session = requireNotNull(secureChat.existingSession(participantIdentity = aliceCard.identity))

val ratchetMessage = RatchetMessage.deserialize(messageData)

val decryptedMessage = session.decryptString(ratchetMessage)

secureChat.storeSession(session)
```
- Use the following code-snippets to decrypt data:

```kotlin
val session = requireNotNull(secureChat.existingSession(participantIdentity = aliceCard.identity))

val ratchetMessage = RatchetMessage.deserialize(messageData)

val decryptedMessage = session.decryptData(ratchetMessage)

secureChat.storeSession(session)
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
