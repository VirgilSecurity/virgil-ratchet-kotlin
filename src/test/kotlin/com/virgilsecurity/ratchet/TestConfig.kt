package com.virgilsecurity.ratchet

import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import java.util.*

class TestConfig {

    companion object {
        val virgilCrypto = VirgilCrypto(false)
        val appId: String by lazy {
            if (System.getProperty("APP_ID") != null)
                System.getProperty("APP_ID")
            else
                System.getenv("APP_ID")
        }
        val apiPrivateKey: VirgilPrivateKey by lazy {
            (if (System.getProperty("API_PRIVATE_KEY") != null)
                System.getProperty("API_PRIVATE_KEY")
            else
                System.getenv("API_PRIVATE_KEY")).let {
                this.virgilCrypto.importPrivateKey(Base64.getDecoder().decode(it)).privateKey
            }
        }
        val apiPublicKeyId: String by lazy {
            if (System.getProperty("API_PUBLIC_KEY_ID") != null)
                System.getProperty("API_PUBLIC_KEY_ID")
            else
                System.getenv("API_PUBLIC_KEY_ID")
        }
        val serviceURL: String by lazy {
            if (System.getProperty("SERVICE_URL") != null)
                System.getProperty("SERVICE_URL")
            else
                System.getenv("SERVICE_URL")
        }
    }
}