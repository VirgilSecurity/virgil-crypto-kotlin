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

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.apiImplementation.VirgilCrypto
import com.virgilsecurity.apiImplementation.VirgilPrivateKey
import com.virgilsecurity.apiImplementation.VirgilPublicKey
import com.virgilsecurity.crypto.VirgilBase64
import com.virgilsecurity.crypto.VirgilKeyPair
import exception.CryptoException
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.runners.Parameterized.Parameters

import java.io.InputStreamReader
import java.util.ArrayList
import java.util.Arrays

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue

/**
 * @author Andrii Iakovenko
 */
@RunWith(Parameterized::class)
class VirgilCryptoCompatibilityTest
/**
 * Create new instance of [VirgilCryptoCompatibilityTest].
 */
(private var crypto: VirgilCrypto?) {
    private var sampleJson: JsonObject? = null

    @Before
    fun setup() {
        this.crypto = VirgilCrypto()
        this.crypto!!.isUseSHA256Fingerprints = true

        sampleJson = JsonParser().parse(InputStreamReader(this.javaClass.classLoader
                .getResourceAsStream("crypto/crypto_compatibility_data.json"))) as JsonObject
    }

    @Test
    @Throws(CryptoException::class)
    fun decryptFromSingleRecipient() {
        val json = sampleJson!!.getAsJsonObject("encrypt_single_recipient")

        val privateKeyData = VirgilBase64.decode(json.get("private_key").asString)
        val originalData = VirgilBase64.decode(json.get("original_data").asString)
        val cipherData = VirgilBase64.decode(json.get("cipher_data").asString)

        val privateKey = this.crypto!!.importPrivateKey(privateKeyData, null)
        val decryptedData = this.crypto!!.decrypt(cipherData, privateKey)

        assertArrayEquals(originalData, decryptedData)
    }

    @Test
    @Throws(CryptoException::class)
    fun decryptFromMultipleRecipients() {
        val json = sampleJson!!.getAsJsonObject("encrypt_multiple_recipients")

        val privateKeys = ArrayList<VirgilPrivateKey>()
        for (el in json.getAsJsonArray("private_keys")) {
            val privateKeyData = VirgilBase64.decode(el.asString)
            privateKeys.add(this.crypto!!.importPrivateKey(privateKeyData, null))
        }
        val originalData = VirgilBase64.decode(json.get("original_data").asString)
        val cipherData = VirgilBase64.decode(json.get("cipher_data").asString)

        for (privateKey in privateKeys) {
            val decryptedData = this.crypto!!.decrypt(cipherData, privateKey)
            assertArrayEquals(originalData, decryptedData)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun decryptThenVerifySingleRecipient() {
        val json = sampleJson!!.getAsJsonObject("sign_then_encrypt_single_recipient")

        val privateKeyData = VirgilBase64.decode(json.get("private_key").asString)
        val originalData = VirgilBase64.decode(json.get("original_data").asString)
        val cipherData = VirgilBase64.decode(json.get("cipher_data").asString)

        val privateKey = this.crypto!!.importPrivateKey(privateKeyData, null)
        val publicKeyData = VirgilKeyPair.extractPublicKey(privateKeyData, ByteArray(0))
        val publicKey = this.crypto!!.importPublicKey(publicKeyData)

        val decryptedData = this.crypto!!.decryptThenVerify(cipherData, privateKey, Arrays.asList(publicKey))
        assertArrayEquals(originalData, decryptedData)
    }

    @Test
    @Throws(CryptoException::class)
    fun decryptThenVerifyMultipleRecipients() {
        val json = sampleJson!!.getAsJsonObject("sign_then_encrypt_multiple_recipients")

        val privateKeys = ArrayList<VirgilPrivateKey>()
        for (el in json.getAsJsonArray("private_keys")) {
            val privateKeyData = VirgilBase64.decode(el.asString)
            privateKeys.add(this.crypto!!.importPrivateKey(privateKeyData, null))
        }
        val originalData = VirgilBase64.decode(json.get("original_data").asString)
        val cipherData = VirgilBase64.decode(json.get("cipher_data").asString)

        val publicKeyData = VirgilKeyPair.extractPublicKey(privateKeys[0].rawKey, ByteArray(0))
        val publicKey = this.crypto!!.importPublicKey(publicKeyData)

        for (privateKey in privateKeys) {
            val decryptedData = this.crypto!!.decryptThenVerify(cipherData, privateKey, Arrays.asList(publicKey))
            assertArrayEquals(originalData, decryptedData)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun generateSignature() {
        val json = sampleJson!!.getAsJsonObject("generate_signature")

        val privateKeyData = VirgilBase64.decode(json.get("private_key").asString)
        val originalData = VirgilBase64.decode(json.get("original_data").asString)
        val signature = VirgilBase64.decode(json.get("signature").asString)

        val privateKey = this.crypto!!.importPrivateKey(privateKeyData, null)
        val generatedSignature = this.crypto!!.generateSignature(originalData, privateKey)

        assertArrayEquals(signature, generatedSignature)

        val publicKeyData = VirgilKeyPair.extractPublicKey(privateKeyData, ByteArray(0))
        val publicKey = this.crypto!!.importPublicKey(publicKeyData)
        assertTrue(this.crypto!!.verifySignature(signature, originalData, publicKey))
    }

    @Test
    @Throws(CryptoException::class)
    fun decryptThenVerifyMultipleSigners() {
        val json = sampleJson!!.getAsJsonObject("sign_then_encrypt_multiple_signers")

        val privateKeyData = VirgilBase64.decode(json.get("private_key").asString)
        val originalData = VirgilBase64.decode(json.get("original_data").asString)
        val cipherData = VirgilBase64.decode(json.get("cipher_data").asString)
        val publicKeys = ArrayList<VirgilPublicKey>()
        for (el in json.getAsJsonArray("public_keys")) {
            val publicKeyData = VirgilBase64.decode(el.asString)
            publicKeys.add(this.crypto!!.importPublicKey(publicKeyData))
        }

        val privateKey = this.crypto!!.importPrivateKey(privateKeyData, null)

        val decryptedData = this.crypto!!.decryptThenVerify(cipherData, privateKey, publicKeys)
        assertArrayEquals(originalData, decryptedData)
    }

    companion object {

        @JvmStatic
        @Parameterized.Parameters
        fun cryptos(): Collection<VirgilCrypto> {
            val cryptos = ArrayList<VirgilCrypto>()

            cryptos.add(VirgilCrypto(true))

            val crypto = VirgilCrypto()
            crypto.isUseSHA256Fingerprints = true
            cryptos.add(crypto)

            return cryptos
        }
    }

}
