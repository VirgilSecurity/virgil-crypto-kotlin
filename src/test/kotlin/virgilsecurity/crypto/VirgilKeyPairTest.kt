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
package virgilsecurity.crypto

import com.virgilsecurity.crypto.VirgilKeyPair
import org.junit.Test

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue

/**
 * Unit tests for [VirgilKeyPair]
 *
 * @author Andrii Iakovenko
 */
class VirgilKeyPairTest {

    @Test
    fun privateKeyToPEM() {
        val keyPair = VirgilKeyPair.generateRecommended()

        val key = VirgilKeyPair.privateKeyToPEM(keyPair.privateKey())
        assertNotNull(key)
    }

    @Test
    fun privateKeyToPEM_withPassword() {
        val keyPair = VirgilKeyPair.generateRecommended(PWD)

        val key = VirgilKeyPair.privateKeyToPEM(keyPair.privateKey(), PWD)
        assertNotNull(key)
        assertTrue(key.size > 0)
    }

    @Test
    fun privateKeyToDER() {
        val key = VirgilKeyPair.privateKeyToDER(PRIVATE_KEY_PEM)
        assertNotNull(key)
        assertTrue(key.size > 0)
    }

    companion object {

        private val PWD = "12345678".toByteArray()
        private val PRIVATE_KEY_PEM = ("-----BEGIN PRIVATE KEY-----\n"
                + "MC4CAQAwBQYDK2VwBCIEINzRBu+EahDeUI8R9GQNGBRl1wKNJzPlZbXWpyiZL7/o\n" + "-----END PRIVATE KEY-----")
                .toByteArray()

        private val PRIVATE_KEY_WITH_PWD_PEM = ("-----BEGIN ENCRYPTED PRIVATE KEY-----"
                + "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBAh2/nefw5GKD1v2GzZ"
                + "GLijAgIRljAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEE1eLCunQ0uoV/LMzac6"
                + "1lQEQLyX0mupWyvmgnAtameTQXEz9gson2ziiopjO1Wk59PkKjB1ovI3ZelARFPm" + "o0Eso0K/Qzb8MOBI6WCEMVpW4Qo="
                + "-----END ENCRYPTED PRIVATE KEY------").toByteArray()
    }

}
