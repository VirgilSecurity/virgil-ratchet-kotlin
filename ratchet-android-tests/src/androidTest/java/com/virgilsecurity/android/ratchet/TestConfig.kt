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

package com.virgilsecurity.android.ratchet

import android.content.Context
import android.support.test.InstrumentationRegistry
import android.util.Base64
import com.virgilsecurity.ratchet_android_tests.BuildConfig
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import java.util.logging.Level

class TestConfig {

    companion object {
        val virgilCrypto = VirgilCrypto(false)

        const val appId: String = BuildConfig.APP_ID

        val apiPrivateKey: VirgilPrivateKey by lazy {
            virgilCrypto.importPrivateKey(Base64.decode(BuildConfig.API_PRIVATE_KEY, Base64.NO_WRAP)).privateKey
        }

        const val apiPublicKeyId: String = BuildConfig.API_PUBLIC_KEY_ID

        val serviceURL: String by lazy { BuildConfig.SERVICE_URL }

        val cardsServiceURL: String by lazy { "$serviceURL/card/v5/" }

        val context: Context = InstrumentationRegistry.getTargetContext()

        val logLevel: Level = Level.ALL
    }
}