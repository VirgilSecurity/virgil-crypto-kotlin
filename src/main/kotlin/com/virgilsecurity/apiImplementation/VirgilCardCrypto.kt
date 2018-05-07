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

package com.virgilsecurity.apiImplementation

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


import com.virgilsecurity.api.crypto.CardCrypto
import com.virgilsecurity.api.crypto.PrivateKey
import com.virgilsecurity.api.crypto.PublicKey
import com.virgilsecurity.api.exception.CryptoException

/**
 * The [VirgilCardCrypto] class provides a cryptographic operations in applications, such as hashing, signature
 * generation and verification, and encryption and decryption.
 *
 * @see CardCrypto
 *
 * @see PrivateKey
 *
 * @see PublicKey
 *
 * @see VirgilCrypto
 */
class VirgilCardCrypto : CardCrypto {

    /**
     * Gets Virgil Crypto.
     *
     * @return the virgil crypto
     */
    var virgilCrypto: VirgilCrypto? = null
        private set

    /**
     * Instantiates a new Virgil card crypto.
     */
    constructor() {
        this.virgilCrypto = VirgilCrypto()
    }

    /**
     * Create new instance of [VirgilCardCrypto].
     *
     * @param virgilCrypto
     * The Virgil Crypto.
     */
    constructor(virgilCrypto: VirgilCrypto) {
        this.virgilCrypto = virgilCrypto
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.CardCrypto#exportPublicKey(com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Throws(CryptoException::class)
    override fun exportPublicKey(publicKey: PublicKey): ByteArray {
        if (publicKey !is VirgilPublicKey)
            throw CryptoException("VirgilCrypto -> 'publicKey' should be of 'VirgilPublicKey' type")

        return virgilCrypto!!.exportPublicKey(publicKey)
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.CardCrypto#generateSHA512(byte[])
     */
    @Throws(CryptoException::class)
    override fun generateSHA512(data: ByteArray): ByteArray {
        return virgilCrypto!!.generateHash(data)
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.CardCrypto#generateSignature(byte[], com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Throws(CryptoException::class)
    override fun generateSignature(data: ByteArray, privateKey: PrivateKey): ByteArray {
        if (privateKey !is VirgilPrivateKey)
            throw CryptoException("VirgilCrypto -> 'privateKey' should be of 'VirgilPrivateKey' type")

        return virgilCrypto!!.generateSignature(data, privateKey)
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.CardCrypto#importPublicKey(byte[])
     */
    @Throws(CryptoException::class)
    override fun importPublicKey(data: ByteArray): PublicKey {
        return virgilCrypto!!.importPublicKey(data)
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.CardCrypto#verifySignature(byte[], byte[],
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Throws(CryptoException::class)
    override fun verifySignature(signature: ByteArray, data: ByteArray, publicKey: PublicKey): Boolean {
        if (publicKey !is VirgilPublicKey)
            throw CryptoException("VirgilCrypto -> 'publicKey' should be of 'VirgilPublicKey' type")

        return virgilCrypto!!.verifySignature(signature, data, publicKey)
    }
}
