/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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
package virgilsecurity.amiImplementation

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.apiImplementation.*
import com.virgilsecurity.crypto.VirgilHash
import com.virgilsecurity.crypto.VirgilHash.Algorithm
import com.virgilsecurity.crypto.VirgilSigner
import crypto.KeysType
import crypto.PrivateKey
import crypto.PublicKey
import exception.CryptoException
import org.junit.Before
import org.junit.Ignore
import org.junit.Test

import javax.xml.bind.DatatypeConverter
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.Arrays

import org.junit.Assert.*

/**
 * @author Andrii Iakovenko
 */
class CryptoFormatsTests {

    private var crypto: VirgilCrypto? = null
    private var sampleJson: JsonObject? = null

    @Before
    fun setup() {
        this.crypto = VirgilCrypto()
        sampleJson = JsonParser().parse(InputStreamReader(this.javaClass.classLoader
                .getResourceAsStream("crypto/crypto_formats_data.json"))) as JsonObject
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_30() {
        val data = sampleJson!!.get("STC-30").asString.toByteArray(StandardCharsets.UTF_8)
        val keyPair = this.crypto!!.generateKeys()

        // Sign with Virgil Crypto
        val signature = this.crypto!!.generateSignature(data, keyPair.privateKey)
        assertNotNull(signature)

        // Sign with Crypto
        VirgilSigner(Algorithm.SHA512).use { signer ->
            val signature2 = signer.sign(data, keyPair.privateKey.rawKey)
            assertArrayEquals(signature2, signature)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_31_generateKeys() {
        // Generate keypair
        val keyPair = this.crypto!!.generateKeys()
        assertNotNull(keyPair)
        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.privateKey)

        // Export key
        val exportedPrivateKey = this.crypto!!.exportPrivateKey(keyPair.privateKey, null)
        assertNotNull(exportedPrivateKey)

        val exportedPrivateKeyWithPassword = this.crypto!!.exportPrivateKey(keyPair.privateKey, "qwerty")
        assertNotNull(exportedPrivateKeyWithPassword)

        val exportedPublicKey = this.crypto!!.exportPublicKey(keyPair.publicKey)
        assertNotNull(exportedPublicKey)
    }

    @Test
    @Ignore
    @Throws(CryptoException::class)
    fun STC_31_generateMultipleKeys() {
        // generate multiple key pairs
        for (keyType in KeysType.values()) {
            try {
                val keyPair = this.crypto!!.generateKeys(keyType)
                assertNotNull(keyPair)
                assertNotNull(keyPair.publicKey)
                assertNotNull(keyPair.privateKey)

                // Export key
                val exportedPrivateKey = this.crypto!!.exportPrivateKey(keyPair.privateKey, null)
                assertNotNull(exportedPrivateKey)

                val exportedPrivateKeyWithPassword = this.crypto!!.exportPrivateKey(keyPair.privateKey, "qwerty")
                assertNotNull(exportedPrivateKeyWithPassword)

                val exportedPublicKey = this.crypto!!.exportPublicKey(keyPair.publicKey)
                assertNotNull(exportedPublicKey)
            } catch (e: Exception) {
                fail("Failed test for key: " + keyType + ": " + e.message)
            }

        }
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_31_importPrivateKey() {
        val json = sampleJson!!.getAsJsonObject("STC-31")
        val keyData = DatatypeConverter.parseBase64Binary(json.get("private_key1").asString)
        val privateKey = this.crypto!!.importPrivateKey(keyData)
        assertNotNull(privateKey)

        val exportedPrivateKey = this.crypto!!.exportPrivateKey(privateKey, null)
        assertNotNull(exportedPrivateKey)
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_31_importPrivateKeyWithPassword() {
        val json = sampleJson!!.getAsJsonObject("STC-31")
        val keyData = DatatypeConverter.parseBase64Binary(json.get("private_key2").asString)
        val password = json.get("private_key2_password").asString
        val privateKey = this.crypto!!.importPrivateKey(keyData, password)
        assertNotNull(privateKey)

        val exportedPrivateKey = this.crypto!!.exportPrivateKey(privateKey, password)
        assertNotNull(exportedPrivateKey)
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_32() {
        val keyData = DatatypeConverter.parseBase64Binary(sampleJson!!.get("STC-32").asString)
        val publicKey = this.crypto!!.importPublicKey(keyData)
        assertNotNull(publicKey)

        val exportedPublicKey = this.crypto!!.exportPublicKey(publicKey)
        assertNotNull(exportedPublicKey)
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_33_sha512() {
        val keyPair = this.crypto!!.generateKeys()
        val publicKey = keyPair.publicKey

        VirgilHash(Algorithm.SHA512).use { hasher ->
            val hash = hasher.hash(publicKey.rawKey)
            val id = Arrays.copyOf(hash, 8)

            assertArrayEquals(id, publicKey.identifier)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun STC_33_sha256() {
        this.crypto!!.isUseSHA256Fingerprints = true

        val keyPair = this.crypto!!.generateKeys()
        val publicKey = keyPair.publicKey

        VirgilHash(Algorithm.SHA256).use { hasher ->
            val id = hasher.hash(publicKey.rawKey)

            assertArrayEquals(id, publicKey.identifier)
        }
    }

}
