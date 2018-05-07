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

import com.virgilsecurity.api.crypto.KeysType
import com.virgilsecurity.api.crypto.PrivateKey
import com.virgilsecurity.api.crypto.PrivateKeyExporter
import com.virgilsecurity.api.exception.CryptoException

/**
 * The [VirgilPrivateKeyExporter] represents and object that implements [PrivateKeyExporter] and provides a
 * list of methods that lets user to export and import private key.
 */
class VirgilPrivateKeyExporter : PrivateKeyExporter {

    private var virgilCrypto: VirgilCrypto
    private var password: String? = null

    /**
     * Create new instance of [VirgilPrivateKeyExporter] using [VirgilCrypto] with default [KeysType]
     * - `FAST_EC_ED25519`.
     */
    constructor() {
        virgilCrypto = VirgilCrypto(KeysType.FAST_EC_ED25519)
    }

    /**
     * Create new instance of [VirgilPrivateKeyExporter] using [VirgilCrypto] with default [KeysType]
     * - `FAST_EC_ED25519` and specified `password`.
     *
     * @param password
     * The password for private key.
     */
    constructor(password: String?) {
        this.password = password

        virgilCrypto = VirgilCrypto(KeysType.FAST_EC_ED25519)
    }

    /**
     * Create new instance of [VirgilPrivateKeyExporter].
     *
     * @param virgilCrypto
     * The [VirgilCrypto].
     */
    constructor(virgilCrypto: VirgilCrypto) {

        this.virgilCrypto = virgilCrypto
    }

    /**
     * Create new instance of [VirgilPrivateKeyExporter] with specified `password`.
     *
     * @param virgilCrypto
     * the Virgil Crypto
     * @param password
     * the password for private key
     */
    constructor(virgilCrypto: VirgilCrypto, password: String?) {
        this.virgilCrypto = virgilCrypto
        this.password = password
    }

    /**
     * Exports the `privateKey` into material representation. If [VirgilCrypto] was instantiated with
     * `password` then it will be used to export private key.
     *
     * @param privateKey
     * the private key
     * @return Private key in material representation of `byte[]`.
     * @throws CryptoException
     * if problems occurred while exporting key
     */
    @Throws(CryptoException::class)
    override fun exportPrivateKey(privateKey: PrivateKey): ByteArray {
        if (privateKey !is VirgilPrivateKey)
            throw CryptoException("VirgilAccessTokenSigner -> 'privateKey' should be of 'VirgilPrivateKey' type")

        return virgilCrypto.exportPrivateKey(privateKey, password)
    }

    /**
     * Imports the private key from its material representation. If [VirgilCrypto] was instantiated with
     * `password` then it will be used to import private key.
     *
     * @param data
     * The private key material representation bytes.
     * @return The instance of [PrivateKey] imported.
     * @throws CryptoException
     * if problems occurred while importing key.
     */
    @Throws(CryptoException::class)
    override fun importPrivateKey(data: ByteArray): PrivateKey {
        return virgilCrypto.importPrivateKey(data, password)
    }
}
