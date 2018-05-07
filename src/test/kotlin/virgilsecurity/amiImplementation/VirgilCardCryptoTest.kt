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

import com.virgilsecurity.apiImplementation.VirgilCardCrypto
import com.virgilsecurity.apiImplementation.VirgilPublicKey
import com.virgilsecurity.crypto.VirgilBase64
import crypto.PrivateKey
import crypto.PublicKey
import exception.CryptoException
import org.junit.Before
import org.junit.Ignore
import org.junit.Test

import java.nio.charset.StandardCharsets

import org.hamcrest.CoreMatchers.instanceOf
import org.junit.Assert.*

/**
 * @author Andrii Iakovenko
 */
class VirgilCardCryptoTest {

    private var cardCrypto: VirgilCardCrypto? = null
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    @Before
    @Throws(CryptoException::class)
    fun setup() {
        this.cardCrypto = VirgilCardCrypto()

        val keyPair = this.cardCrypto!!.virgilCrypto!!.generateKeys()
        this.privateKey = keyPair.privateKey
        this.publicKey = keyPair.publicKey
    }

    @Test
    @Throws(CryptoException::class)
    fun exportPublicKey() {
        val keyData = this.cardCrypto!!.exportPublicKey(this.publicKey!!)
        assertNotNull(keyData)
    }

    @Test(expected = CryptoException::class)
    @Throws(CryptoException::class)
    fun exportPublicKey_wrongKey() {
        val key = object : PublicKey {

        }
        this.cardCrypto!!.exportPublicKey(key)
    }

    @Test
    @Ignore
    @Throws(CryptoException::class)
    fun generateSHA512() {
        val hash = this.cardCrypto!!.generateSHA512(TEST_DATA)
        assertNotNull(hash)
        assertArrayEquals(
                VirgilBase64
                        .decode("UVRFAY8h/41lGy4Jm82uLcbhseXLS852XZ2rE7kH8wJvSneUkpu04NmFqwhtWuz78P+T63xMhxEW0wXP0B21dA=="),
                hash)
    }

    @Test
    @Throws(CryptoException::class)
    fun generateSignature() {
        val signature = this.cardCrypto!!.generateSignature(TEST_DATA, this.privateKey!!)

        assertNotNull(signature)
    }

    @Test(expected = CryptoException::class)
    @Throws(CryptoException::class)
    fun generateSignature_wrongKey() {
        val key = object : PrivateKey {

        }
        this.cardCrypto!!.generateSignature(TEST_DATA, key)
    }

    @Test
    fun getVirgilCrypto() {
        val crypto = this.cardCrypto!!.virgilCrypto
        assertNotNull(crypto)
    }

    @Test
    @Throws(CryptoException::class)
    fun importPublicKey() {
        val exportedKeyData = this.cardCrypto!!.exportPublicKey(this.publicKey!!)
        val importedPublicKey = this.cardCrypto!!.importPublicKey(exportedKeyData)

        assertNotNull(importedPublicKey)
        assertThat(importedPublicKey, instanceOf(VirgilPublicKey::class.java))
    }

    @Test(expected = CryptoException::class)
    @Throws(CryptoException::class)
    fun importPublicKey_wrongData() {
        this.cardCrypto!!.importPublicKey(TEST_DATA)
    }

    @Test
    @Throws(CryptoException::class)
    fun verifySignature() {
        val signature = this.cardCrypto!!.generateSignature(TEST_DATA, this.privateKey!!)
        assertTrue(this.cardCrypto!!.verifySignature(signature, TEST_DATA, this.publicKey!!))
    }

    @Test
    @Throws(CryptoException::class)
    fun verifySignature_invalidSignature() {
        val signature = this.cardCrypto!!.generateSignature(TEST_DATA, this.privateKey!!)
        assertFalse(this.cardCrypto!!.verifySignature(signature, "$TEST_TEXT ".toByteArray(), this.publicKey!!))
    }

    companion object {

        private val TEST_TEXT = "Lorem Ipsum is simply dummy text of the printing and typesetting industry."
        private val TEST_DATA = TEST_TEXT.toByteArray(StandardCharsets.UTF_8)
    }
}
