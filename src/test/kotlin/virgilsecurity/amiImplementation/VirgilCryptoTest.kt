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

import com.virgilsecurity.apiImplementation.VirgilCrypto
import com.virgilsecurity.apiImplementation.VirgilPrivateKey
import com.virgilsecurity.apiImplementation.VirgilPublicKey
import crypto.KeysType
import exception.CryptoException
import exception.VirgilException
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.runners.Parameterized.Parameters

import java.io.*
import java.util.*

import org.junit.Assert.*

/**
 * Unit tests for [VirgilCrypto]
 *
 * @author Andrii Iakovenko
 */
@RunWith(Parameterized::class)
class VirgilCryptoTest
/**
 * Create new instance of [VirgilCryptoTest].
 */
(private val keysType: KeysType) {
    private var crypto: VirgilCrypto? = null

    @Before
    fun setup() {
        crypto = VirgilCrypto(this.keysType)
    }

    @Test
    @Throws(VirgilException::class)
    fun decrypt() {
        val privateKeys = ArrayList<VirgilPrivateKey>()
        val recipients = ArrayList<VirgilPublicKey>()
        for (i in 0..99) {
            val keyPair = crypto!!.generateKeys()
            privateKeys.add(keyPair.privateKey)
            recipients.add(keyPair.publicKey)
        }
        val encrypted = crypto!!.encrypt(TEXT.toByteArray(), recipients)
        for (privateKey in privateKeys) {
            val decrypted = crypto!!.decrypt(encrypted, privateKey)
            assertArrayEquals(TEXT.toByteArray(), decrypted)
        }
    }

    @Test
    @Throws(IOException::class, VirgilException::class)
    fun decrypt_stream() {
        val privateKeys = ArrayList<VirgilPrivateKey>()
        val recipients = ArrayList<VirgilPublicKey>()
        for (i in 0..0) {
            val keyPair = crypto!!.generateKeys()
            privateKeys.add(keyPair.privateKey)
            recipients.add(keyPair.publicKey)
        }
        val encrypted = crypto!!.encrypt(TEXT.toByteArray(), recipients)
        ByteArrayInputStream(encrypted).use { `is` ->
            ByteArrayOutputStream().use { os ->
                for (privateKey in privateKeys) {
                    crypto!!.decrypt(`is`, os, privateKey)

                    val decrypted = os.toByteArray()

                    assertArrayEquals(TEXT.toByteArray(), decrypted)
                }
            }
        }
    }

    @Test
    @Ignore
    fun decryptThenVerify() {

    }

    @Test
    @Throws(VirgilException::class)
    fun encrypt() {
        val recipients = ArrayList<VirgilPublicKey>()
        for (i in 0..99) {
            recipients.add(crypto!!.generateKeys().publicKey)
        }
        val encrypted = crypto!!.encrypt(TEXT.toByteArray(), recipients)

        assertNotNull(encrypted)
    }

    @Test
    @Throws(VirgilException::class)
    fun encrypt_noRecipients_success() {
        val encrypted = crypto!!.encrypt(TEXT.toByteArray(), emptyList())

        assertNotNull(encrypted)
    }

    @Test
    @Throws(IOException::class, CryptoException::class)
    fun encrypt_stream() {
        val recipients = ArrayList<VirgilPublicKey>()
        for (i in 0..99) {
            recipients.add(crypto!!.generateKeys().publicKey)
        }
        ByteArrayOutputStream().use { os -> crypto!!.encrypt(ByteArrayInputStream(TEXT.toByteArray()), os, recipients) }
    }

    @Test
    @Throws(CryptoException::class)
    fun exportPrivateKey_noPassword() {
        val keyPair = crypto!!.generateKeys()
        val key = crypto!!.exportPrivateKey(keyPair.privateKey, null)

        assertNotNull(key)
        assertTrue(key.size > 0)
    }

    @Test
    @Throws(CryptoException::class)
    fun exportPrivateKey_withPassword() {
        val keyPair = crypto!!.generateKeys()
        val key = crypto!!.exportPrivateKey(keyPair.privateKey, PASSWORD)

        assertNotNull(key)
        assertTrue(key.size > 0)
    }

    @Test
    @Throws(CryptoException::class)
    fun exportPublicKey() {
        val keyPair = crypto!!.generateKeys()

        val key = crypto!!.exportPublicKey(keyPair.publicKey)

        assertNotNull(key)
        assertTrue(key.size > 0)
    }

    @Test
    @Throws(CryptoException::class)
    fun generateKeys() {
        val keyPair = crypto!!.generateKeys()

        assertNotNull(keyPair)

        val publicKey = keyPair.publicKey
        assertNotNull(publicKey)
        assertNotNull(publicKey.identifier)
        assertNotNull(publicKey.rawKey)

        val privateKey = keyPair.privateKey
        assertNotNull(privateKey)
        assertNotNull(privateKey.identifier)
        assertNotNull(privateKey.rawKey)
    }

    @Test
    @Throws(CryptoException::class)
    fun generateSignature() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        val signature = crypto!!.generateSignature(TEXT.toByteArray(), keyPair.privateKey)

        assertNotNull(signature)
    }

    @Test
    @Throws(CryptoException::class)
    fun generateSignature_stream() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        val signature = crypto!!.generateSignature(ByteArrayInputStream(TEXT.toByteArray()), keyPair.privateKey)

        assertNotNull(signature)
    }

    @Test
    @Throws(CryptoException::class)
    fun importPrivateKey_noPassword() {
        val keyPair = crypto!!.generateKeys()

        val keyData = crypto!!.exportPrivateKey(keyPair.privateKey, null)

        val importedKey = crypto!!.importPrivateKey(keyData, null)

        assertNotNull(importedKey)
        assertNotNull(importedKey.identifier)
        assertNotNull(importedKey.rawKey)
        assertArrayEquals(keyPair.privateKey.identifier, importedKey.identifier)
        assertArrayEquals(keyPair.privateKey.rawKey, importedKey.rawKey)
    }

    @Test
    @Throws(CryptoException::class)
    fun importPrivateKey_withPassword() {
        val keyPair = crypto!!.generateKeys()
        val keyData = crypto!!.exportPrivateKey(keyPair.privateKey, PASSWORD)

        val importedKey = crypto!!.importPrivateKey(keyData, PASSWORD)

        assertNotNull(importedKey)
        assertNotNull(importedKey.identifier)
        assertNotNull(importedKey.rawKey)
        assertArrayEquals(keyPair.privateKey.identifier, importedKey.identifier)
        assertArrayEquals(keyPair.privateKey.rawKey, importedKey.rawKey)
    }

    @Test(expected = CryptoException::class)
    @Throws(CryptoException::class)
    fun importPrivateKey_withWrongPassword() {
        val keyPair = crypto!!.generateKeys()
        val keyData = crypto!!.exportPrivateKey(keyPair.privateKey, PASSWORD)

        crypto!!.importPrivateKey(keyData, PASSWORD + "1")
    }

    @Test
    @Throws(CryptoException::class)
    fun importPublicKey() {
        val keyPair = crypto!!.generateKeys()

        val keyData = crypto!!.exportPublicKey(keyPair.publicKey)
        val publicKey = crypto!!.importPublicKey(keyData)

        assertNotNull(publicKey)
        assertNotNull(publicKey.identifier)
        assertNotNull(publicKey.rawKey)
        assertArrayEquals(keyPair.publicKey.identifier, publicKey.identifier)
        assertArrayEquals(keyPair.publicKey.rawKey, publicKey.rawKey)
    }

    @Test
    @Throws(CryptoException::class)
    fun sign_stream_compareToByteArraySign() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        val signature = crypto!!.generateSignature(TEXT.toByteArray(), keyPair.privateKey)
        val streamSignature = crypto!!.generateSignature(ByteArrayInputStream(TEXT.toByteArray()),
                keyPair.privateKey)

        assertNotNull(signature)
        assertNotNull(streamSignature)
        assertArrayEquals(signature, streamSignature)
    }

    @Test
    @Ignore
    fun signThenEncrypt() {

    }

    @Test
    fun toVirgilKeyPairType() {
        for (keysType in KeysType.values()) {
            val type = VirgilCrypto.toVirgilKeyPairType(keysType)
            assertNotNull(type)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun verifySignature() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        val signature = crypto!!.generateSignature(TEXT.toByteArray(), keyPair.privateKey)
        val valid = crypto!!.verifySignature(signature, TEXT.toByteArray(), keyPair.publicKey)

        assertTrue(valid)
    }

    @Test
    @Throws(CryptoException::class)
    fun verifySignature_invalidSignature() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        crypto!!.generateSignature(TEXT.toByteArray(), keyPair.privateKey)
        val valid = crypto!!.verifySignature(INVALID_SIGNATURE, TEXT.toByteArray(), keyPair.publicKey)

        assertFalse(valid)
    }

    @Test
    @Throws(CryptoException::class)
    fun verifySignature_stream() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        val signature = crypto!!.generateSignature(TEXT.toByteArray(), keyPair.privateKey)
        val valid = crypto!!.verifySignature(signature, ByteArrayInputStream(TEXT.toByteArray()),
                keyPair.publicKey)

        assertTrue(valid)
    }

    @Test
    @Throws(CryptoException::class)
    fun verifySignature_stream_invalidSignature() {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return
        }
        val keyPair = crypto!!.generateKeys()
        crypto!!.generateSignature(TEXT.toByteArray(), keyPair.privateKey)
        val valid = crypto!!.verifySignature(INVALID_SIGNATURE, ByteArrayInputStream(TEXT.toByteArray()),
                keyPair.publicKey)

        assertFalse(valid)
    }

    companion object {

        private val TEXT = "This text is used for unit tests"
        private val PASSWORD = "ThisIsPassWoRd2016"
        private val INVALID_SIGNATURE = byteArrayOf(48, 88, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 2, 5, 0, 4, 71, 48, 69, 2, 33, 0, -108, -6, -82, 29, -38, 103, -13, 42, 101, 76, -34, -53, -96, -70, 85, 80, 0, 88, 77, 48, 9, -100, 81, 39, -51, -125, -102, -107, -108, 14, -88, 7, 2, 32, 13, -71, -99, 8, -69, -77, 30, 98, 20, -25, 60, 125, -19, 67, 12, -30, 65, 93, -29, -92, -58, -91, 91, 50, -111, -79, 50, -123, -39, 36, 48, -20)

        @JvmStatic
        @Parameterized.Parameters
        fun params(): Array<KeysType> {
            val values = HashSet(Arrays.asList(*KeysType.values()))
            // Skip RSA test because they are too slow
            values.remove(KeysType.RSA_3072)
            values.remove(KeysType.RSA_4096)
            values.remove(KeysType.RSA_8192)
            return values.toTypedArray()
        }
    }
}
