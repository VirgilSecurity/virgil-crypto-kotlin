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
import com.virgilsecurity.apiImplementation.VirgilPrivateKeyExporter
import exception.CryptoException
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull

/**
 * @author Andrii Iakovenko
 */
@RunWith(Parameterized::class)
class VirgilPrivateKeyExporterTest(val exporter: VirgilPrivateKeyExporter,
                                   val password: String?) {

    private var crypto: VirgilCrypto? = null
    private var privateKey: VirgilPrivateKey? = null

    @Before
    @Throws(CryptoException::class)
    fun setup() {
        this.crypto = VirgilCrypto()
        this.privateKey = this.crypto!!.generateKeys().privateKey
    }

    @Test
    @Throws(CryptoException::class)
    fun exportPrivateKey() {
        val exportedKeyData = exporter.exportPrivateKey(privateKey!!)
        assertNotNull(exportedKeyData)
    }

    @Test
    @Throws(CryptoException::class)
    fun importPrivateKey() {
        val exportedKeyData = exporter.exportPrivateKey(privateKey!!)

        val importedKey = exporter.importPrivateKey(exportedKeyData) as VirgilPrivateKey
        assertNotNull(importedKey)
        assertEquals(privateKey, importedKey)
    }

    @Test(expected = CryptoException::class)
    @Throws(CryptoException::class)
    fun importPrivateKey_invalidData() {
        exporter.importPrivateKey("wrong_data".toByteArray())
    }

    companion object {

        @JvmStatic
        @Parameterized.Parameters
        fun params(): Collection<Array<out Any?>> {
            return listOf(
                    arrayOf(VirgilPrivateKeyExporter(), null),
                    arrayOf(VirgilPrivateKeyExporter(VirgilCrypto()), null),
                    arrayOf(VirgilPrivateKeyExporter(VirgilCrypto(), null), null),
                    arrayOf(VirgilPrivateKeyExporter(VirgilCrypto(), "PASSWORD"), "PASSWORD"))
        }
    }

}
