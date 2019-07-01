# Virgil Security Ratchet Java/Kotlin SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-ratchet-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-ratchet-kotlin)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ratchet)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Register Users](#register-users) | [Chat Example](#chat-example) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of services and open source libraries for adding security to any application.
Virgil Security is presenting an implementation of the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) algorithm, which is used by parties to exchange encrypted messages based on a shared secret key. The implementation includes:
- **Virgil Perfect Forward Secrecy (PFS) service** – a standalone web-service that is dedicated to managing one-time keys and long-time keys that are based on their Identity Public Keys (public keys that are contained in user cards published on Virgil Cards service);
- **Ratchet SDK** – interacts with PFS service for publishing and managing one-time keys and long-time keys and interacts with Virgil Cards service for retrieving user's indentity cards which the OTK and LTK are based on. The parties derive new keys for every Double Ratchet message so that previous private keys cannot be calculated from new ones. The parties that participate in the communication also send Diffie-Hellman public values attached to their messages. The results of Diffie-Hellman calculations are mixed into the derived keys so that the new private keys cannot be calculated from the previous ones.

Following this, the parties will use the Double Ratchet SDK to initialize chat session and send and receive encrypted messages. And as a result, by adding Virgil Perfect Forward Secrecy (PFS) to your encrypted communication you prevent a possibly compromised user's long time private key (private key) from affecting the confidentiality of past communications.


## SDK Features
- communicate with Virgil PFS Service
- manage users' OTK and LTK keys
- use Virgil [Crypto library][_virgil_crypto]

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

Make sure that you have already registered at the [Virgil Dashboard][_dashboard] and created an E2EE V5 application.

In Virgil every user has a **Private Key** and is represented with a **Virgil Card**, which contains a Public Key and user's identity.

Using Identity Cards, we generate special Cards that have their own life-time:
* **One-time Key (OTK)**
* **Long-time Key (LTK)**

For each session you can use new OTK and delete it after session is finished.

To create user's Virgil Cards, you can use the following code from [this guide](https://developer.virgilsecurity.com/docs/how-to/public-key-management/v5/create-card).


## Chat Example

To begin communicating with PFS service, every user must run the initialization:

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

Then Sender establishes a secure PFS conversation with Receiver, encrypts and sends the message:

```kotlin
// prepare a message
val messageToEncrypt = "Hello, Bob!"

val startNewSessionAsSenderListener = object : OnResultListener<SecureSession> {
    override fun onSuccess(result: SecureSession) {
        val encryptedMessage = encrypt(result, messageToEncrypt)
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
}

secureChat.existingSession(participantIdentity = bobCard.identity).run {
    if (this != null) {
        val encryptedMessage = encrypt(this, messageToEncrypt)
    } else {
        // start new session with recipient if session wasn't initialized yet
        secureChat.startNewSessionAsSender(receiverCard = bobCard).addCallback(startNewSessionAsSenderListener)
    }
}

private fun encrypt(session: SecureSession, messageToEncrypt: String): ByteArray {
    val ratchetMessage = session.encrypt(str = messageToEncrypt)
    return ratchetMessage.serialize()
}
```

Receiver decrypts the incoming message using the conversation he has just created:

```kotlin
val ratchetMessage = RatchetMessage.deserialize(encryptedMessage)

val secureSession = secureChat.existingSession(participantIdentity = aliceCard.identity)
        // start new session with recipient if session wasn't initialized yet
        ?: secureChat.startNewSessionAsReceiver(senderCard = aliceCard, ratchetMessage = ratchetMessage)

val decryptedMessage = secureSession.decryptString(ratchetMessage)
```

With the open session, which works in both directions, Sender and Receiver can continue PFS-encrypted communication.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).


[_dashboard]: https://dashboard.virgilsecurity.com/
[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto-c
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_use_cases]: https://developer.virgilsecurity.com/docs/use-cases
[_use_case_pfs]:https://developer.virgilsecurity.com/docs/swift/use-cases/v4/perfect-forward-secrecy

