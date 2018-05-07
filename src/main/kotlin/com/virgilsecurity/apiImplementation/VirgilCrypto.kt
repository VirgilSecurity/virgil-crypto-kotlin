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

import com.virgilsecurity.api.crypto.HashAlgorithm
import com.virgilsecurity.api.crypto.KeysType
import com.virgilsecurity.api.exception.*
import com.virgilsecurity.crypto.*
import com.virgilsecurity.crypto.VirgilKeyPair
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * The Virgil's implementation of Crypto.
 *
 * @author Danylo Oliinyk
 *
 * @see VirgilPublicKey
 *
 * @see VirgilPrivateKey
 */
class VirgilCrypto {

    private var defaultKeyPairType: KeysType? = null
    /**
     * @return the useSHA256Fingerprints
     */
    /**
     * @param useSHA256Fingerprints
     * the useSHA256Fingerprints to set
     */
    var isUseSHA256Fingerprints: Boolean = false

    /**
     * Create new instance of [VirgilCrypto].
     *
     * @param useSHA256Fingerprints
     * set this flag to `true` to use SHA256 algorithm when calculating public key identifier
     */
    @JvmOverloads constructor(useSHA256Fingerprints: Boolean = false) {
        this.defaultKeyPairType = KeysType.Default
        this.isUseSHA256Fingerprints = useSHA256Fingerprints
    }

    /**
     * Create new instance of [VirgilCrypto].
     *
     * @param keysType
     * the [KeysType] to be used by default for generating key pair
     */
    constructor(keysType: KeysType) {
        this.defaultKeyPairType = keysType
        this.isUseSHA256Fingerprints = false
    }

    /**
     * Decrypts the specified data using Private key.
     *
     * @param cipherData
     * the ncrypted data bytes to decrypt
     * @param privateKey
     * the private key used for decryption
     * @return Decrypted data bytes.
     * @throws DecryptionException
     * if decryption failed
     */
    @Throws(DecryptionException::class)
    fun decrypt(cipherData: ByteArray, privateKey: VirgilPrivateKey): ByteArray {
        try {
            VirgilCipher().use { cipher ->
                return cipher.decryptWithKey(cipherData, privateKey.identifier,
                        privateKey.rawKey)
            }
        } catch (e: Exception) {
            throw DecryptionException(e)
        }

    }

    /**
     * Decrypts the specified stream using Private key.
     *
     * @param inputStream
     * Encrypted stream for decryption.
     * @param outputStream
     * Output stream for decrypted data.
     * @param privateKey
     * Private key for decryption.
     * @throws DecryptionException
     * if decryption failed
     */
    @Throws(DecryptionException::class)
    fun decrypt(inputStream: InputStream, outputStream: OutputStream, privateKey: VirgilPrivateKey) {
        try {
            VirgilStreamCipher().use { cipher ->
                VirgilStreamDataSource(inputStream).use { dataSource ->
                    VirgilStreamDataSink(outputStream).use { dataSink ->

                        cipher.decryptWithKey(dataSource, dataSink, privateKey.identifier, privateKey.rawKey)
                    }
                }
            }
        } catch (e: IOException) {
            throw DecryptionException(e)
        }

    }

    /**
     * Decrypts and verifies the data.
     *
     * @param cipherData
     * The cipher data.
     * @param privateKey
     * The Private key to decrypt.
     * @param publicKeys
     * The list of trusted public keys for verification, which can contain signer's public key
     * @return The decrypted data.
     * @throws CryptoException
     * if decryption or verification failed
     */
    @Throws(CryptoException::class)
    fun decryptThenVerify(cipherData: ByteArray, privateKey: VirgilPrivateKey, publicKeys: List<VirgilPublicKey>?): ByteArray {
        try {
            VirgilSigner(VirgilHash.Algorithm.SHA512).use { signer ->
                VirgilCipher().use { cipher ->
                    val decryptedData = cipher.decryptWithKey(cipherData, privateKey.identifier,
                            privateKey.rawKey)
                    val signature = cipher.customParams().getData(CUSTOM_PARAM_SIGNATURE)

                    var signerPublicKey: VirgilPublicKey? = null
                    if (publicKeys != null) {
                        val signerId = cipher.customParams().getData(CUSTOM_PARAM_SIGNER_ID)
                        for (publicKey in publicKeys) {
                            if (Arrays.equals(signerId, publicKey.identifier)) {
                                signerPublicKey = publicKey
                                break
                            }
                        }
                    }
                    if (signerPublicKey == null)
                        throw SignatureIsNotValidException()

                    val isValid = signer.verify(decryptedData, signature, signerPublicKey.rawKey)
                    if (!isValid)
                        throw SignatureIsNotValidException()

                    return decryptedData
                }
            }
        } catch (e: Exception) {
            throw CryptoException(e.message)
        }
    }

    /**
     * Encrypts the specified data using recipients Public keys.
     *
     * @param data
     * Raw data bytes for encryption.
     * @param publicKeys
     * List of recipients' public keys.
     * @return Encrypted bytes.
     * @throws EncryptionException
     * if encryption failed
     */
    @Throws(EncryptionException::class)
    fun encrypt(data: ByteArray, publicKeys: List<VirgilPublicKey>): ByteArray {
        try {
            VirgilCipher().use { cipher ->
                for (recipient in publicKeys) {
                    cipher.addKeyRecipient(recipient.identifier, recipient.rawKey)
                }

                return cipher.encrypt(data, true)
            }
        } catch (e: Exception) {
            throw EncryptionException(e)
        }

    }

    /**
     * Encrypts the specified data using recipient's Public key.
     *
     * @param data
     * Raw data bytes for encryption.
     * @param publicKey
     * Recipient's public key.
     * @return Encrypted bytes.
     * @throws EncryptionException
     * if encryption failed
     */
    @Throws(EncryptionException::class)
    fun encrypt(data: ByteArray, publicKey: VirgilPublicKey): ByteArray {
        return encrypt(data, Arrays.asList(publicKey))
    }

    /**
     * Encrypts the specified stream using recipients Public keys.
     *
     * @param inputStream
     * Input stream for encrypted.
     * @param outputStream
     * Output stream for encrypted data.
     * @param publicKeys
     * List of recipients' public keys.
     * @throws EncryptionException
     * if encryption failed
     */
    @Throws(EncryptionException::class)
    fun encrypt(inputStream: InputStream, outputStream: OutputStream, publicKeys: List<VirgilPublicKey>) {
        try {
            VirgilStreamCipher().use { cipher ->
                VirgilStreamDataSource(inputStream).use { dataSource ->
                    VirgilStreamDataSink(outputStream).use { dataSink ->
                        for (recipient in publicKeys) {
                            cipher.addKeyRecipient(recipient.identifier, recipient.rawKey)
                        }

                        cipher.encrypt(dataSource, dataSink, true)
                    }
                }
            }
        } catch (e: IOException) {
            throw EncryptionException(e)
        }

    }

    /**
     * Encrypts the specified stream using recipient's Public key.
     *
     * @param inputStream
     * Input stream for encrypted.
     * @param outputStream
     * Output stream for encrypted data.
     * @param publicKey
     * Recipient's public key.
     * @throws EncryptionException
     * if encryption failed
     */
    @Throws(EncryptionException::class)
    fun encrypt(inputStream: InputStream, outputStream: OutputStream, publicKey: VirgilPublicKey) {
        encrypt(inputStream, outputStream, Arrays.asList(publicKey))
    }

    /**
     * Exports the Private key into material representation.
     *
     * @param privateKey
     * The private key for export.
     * @param password
     * The password.
     * @return Key material representation bytes.
     * @throws CryptoException
     * if key couldn't be exported
     */
    @Throws(CryptoException::class)
    fun exportPrivateKey(privateKey: VirgilPrivateKey, password: String?): ByteArray {
        try {
            if (password == null)
                return VirgilKeyPair.privateKeyToDER(privateKey.rawKey)

            val passwordBytes = password.toByteArray(UTF8_CHARSET)
            val encryptedKey = VirgilKeyPair.encryptPrivateKey(privateKey.rawKey, passwordBytes)

            return VirgilKeyPair.privateKeyToDER(encryptedKey, passwordBytes)
        } catch (e: Exception) {
            throw CryptoException(e)
        }

    }

    /**
     * Exports the Public key into material representation.
     *
     * @param publicKey
     * Public key for export.
     * @return Key material representation bytes.
     * @throws CryptoException
     * if key couldn't be exported
     */
    @Throws(CryptoException::class)
    fun exportPublicKey(publicKey: VirgilPublicKey): ByteArray {
        try {
            return VirgilKeyPair.publicKeyToDER(publicKey.rawKey)
        } catch (e: Exception) {
            throw CryptoException(e)
        }

    }

    /**
     * Extract public key from private key.
     *
     * @param keyData
     * the private key.
     * @param password
     * the password
     * @return the extracted public key.
     */
    @JvmOverloads
    fun extractPublicKey(keyData: VirgilPrivateKey, password: String? = null): VirgilPublicKey {
        if (password != null && password.isEmpty())
            throw IllegalArgumentException("VirgilCrypto -> 'password' should not be empty")

        val publicKeyData: ByteArray = if (password == null)
            VirgilKeyPair.extractPublicKey(keyData.rawKey, ByteArray(0))
        else
            VirgilKeyPair.extractPublicKey(keyData.rawKey, password.toByteArray(UTF8_CHARSET))

        val receiverId = keyData.identifier
        val value = VirgilKeyPair.publicKeyToDER(publicKeyData)

        return VirgilPublicKey(receiverId, value)
    }

    /**
     * @param data
     * the data
     * @return the generated hash
     * @throws CryptoException
     * if crypto hash operation failed
     */
    @Throws(CryptoException::class)
    fun generateHash(data: ByteArray): ByteArray {
        return if (isUseSHA256Fingerprints)
            generateHash(data, HashAlgorithm.SHA256)
        else
            generateHash(data, HashAlgorithm.SHA512)
    }

    /**
     * Computes the hash of specified data.
     *
     * @param data
     * the data
     * @param algorithm
     * the hash algorithm
     * @return the computed hash
     * @throws CryptoException
     * if crypto hash operation failed
     */
    @Throws(CryptoException::class)
    fun generateHash(data: ByteArray, algorithm: HashAlgorithm): ByteArray {
        try {
            createVirgilHash(algorithm).use { hasher -> return hasher.hash(data) }
        } catch (e: Exception) {
            throw CryptoException(e.message)
        }
    }

    /**
     * Generates asymmetric key pair that is comprised of both public and private keys by specified type.
     *
     * @param keysType
     * Type of the generated keys. The possible values can be found in [KeysType].
     * @return Generated key pair.
     * @throws CryptoException
     * if crypto operation failed
     */
    @Throws(CryptoException::class)
    @JvmOverloads
    fun generateKeys(keysType: KeysType? = this.defaultKeyPairType): com.virgilsecurity.apiImplementation.VirgilKeyPair {
        val keyPair = VirgilKeyPair.generate(toVirgilKeyPairType(keysType!!))

        val keyPairId = this.computePublicKeyHash(keyPair.publicKey())

        val publicKey = VirgilPublicKey(keyPairId, VirgilKeyPair.publicKeyToDER(keyPair.publicKey()))
        val privateKey = VirgilPrivateKey(keyPairId,
                VirgilKeyPair.privateKeyToDER(keyPair.privateKey()))

        return com.virgilsecurity.apiImplementation.VirgilKeyPair(publicKey, privateKey)
    }

    /**
     * Signs the specified data using Private key.
     *
     * @param data
     * the raw data bytes for signing
     * @param privateKey
     * the private key for signing
     * @return the calculated signature data
     * @throws SigningException
     * if crypto sign operation failed
     */
    @Throws(SigningException::class)
    fun generateSignature(data: ByteArray, privateKey: VirgilPrivateKey): ByteArray {
        try {
            VirgilSigner(VirgilHash.Algorithm.SHA512).use { signer -> return signer.sign(data, privateKey.rawKey) }
        } catch (e: Exception) {
            throw SigningException(e.message)
        }

    }

    /**
     * Signs the specified stream using Private key.
     *
     * @param stream
     * the stream for signing
     * @param privateKey
     * the private key for signing
     * @return the calculated signature data
     * @throws SigningException
     * if crypto sign operation failed
     */
    @Throws(SigningException::class)
    fun generateSignature(stream: InputStream, privateKey: VirgilPrivateKey): ByteArray {
        try {
            VirgilStreamSigner(VirgilHash.Algorithm.SHA512).use { signer ->
                VirgilStreamDataSource(stream).use { dataSource ->
                    return signer.sign(dataSource, privateKey.rawKey)
                }
            }
        } catch (e: IOException) {
            throw SigningException(e)
        }
    }

    /**
     * Imports the Private key from material representation.
     *
     * @param keyData
     * the private key material representation bytes
     * @param password
     * the private key password
     * @return imported private key
     * @throws CryptoException
     * if key couldn't be imported
     */
    @Throws(CryptoException::class)
    @JvmOverloads
    fun importPrivateKey(keyData: ByteArray, password: String? = null): VirgilPrivateKey {
        try {
            val privateKeyBytes: ByteArray = if (password == null)
                VirgilKeyPair.privateKeyToDER(keyData)
            else
                VirgilKeyPair.decryptPrivateKey(keyData, password.toByteArray(UTF8_CHARSET))

            val publicKey = VirgilKeyPair.extractPublicKey(privateKeyBytes, byteArrayOf())

            val receiverId = computePublicKeyHash(publicKey)
            val value = VirgilKeyPair.privateKeyToDER(privateKeyBytes)

            return VirgilPrivateKey(receiverId, value)
        } catch (e: Exception) {
            throw CryptoException(e)
        }

    }

    /**
     * Imports the Public key from material representation.
     *
     * @param keyData
     * the public key material representation bytes
     * @return an imported public key
     * @throws CryptoException
     * if key couldn't be imported
     */
    @Throws(CryptoException::class)
    fun importPublicKey(keyData: ByteArray): VirgilPublicKey {
        try {
            val receiverId = computePublicKeyHash(keyData)
            val value = VirgilKeyPair.publicKeyToDER(keyData)

            return VirgilPublicKey(receiverId, value)
        } catch (e: Exception) {
            throw CryptoException(e)
        }

    }

    /**
     * Signs and encrypts the data.
     *
     * @param data
     * The data to encrypt.
     * @param privateKey
     * The Private key to sign the data.
     * @param publicKeys
     * The list of Public key recipients to encrypt the data.
     * @return Signed and encrypted data bytes.
     * @throws CryptoException
     * if crypto sing or encrypt operation failed
     */
    @Throws(CryptoException::class)
    fun signThenEncrypt(data: ByteArray, privateKey: VirgilPrivateKey, publicKeys: List<VirgilPublicKey>): ByteArray {
        try {
            VirgilSigner(VirgilHash.Algorithm.SHA512).use { signer ->
                VirgilCipher().use { cipher ->

                    val signature = signer.sign(data, privateKey.rawKey)

                    val customData = cipher.customParams()
                    customData.setData(CUSTOM_PARAM_SIGNATURE, signature)
                    customData.setData(CUSTOM_PARAM_SIGNER_ID, privateKey.identifier)

                    for (publicKey in publicKeys) {
                        cipher.addKeyRecipient(publicKey.identifier, publicKey.rawKey)
                    }
                    return cipher.encrypt(data, true)

                }
            }
        } catch (e: Exception) {
            throw CryptoException(e.message)
        }

    }

    /**
     * Signs and encrypts the data.
     *
     * @param data
     * The data to encrypt.
     * @param privateKey
     * The Private key to sign the data.
     * @param publicKey
     * The recipient's Public key to encrypt the data.
     * @return Signed and encrypted data bytes.
     * @throws CryptoException
     * if crypto sing or encrypt operation failed
     */
    @Throws(CryptoException::class)
    fun signThenEncrypt(data: ByteArray, privateKey: VirgilPrivateKey, publicKey: VirgilPublicKey): ByteArray {
        return signThenEncrypt(data, privateKey, Arrays.asList(publicKey))
    }

    /**
     * Verifies the specified signature using original data and signer's Public key.
     *
     * @param signature
     * Signature bytes for verification.
     * @param data
     * Original data bytes for verification.
     * @param publicKey
     * Signer's public key for verification.
     * @return `true` if signature is valid, `false` otherwise.
     * @throws VerificationException
     * if crypto sing operation failed
     */
    @Throws(VerificationException::class)
    fun verifySignature(signature: ByteArray, data: ByteArray, publicKey: VirgilPublicKey): Boolean {
        try {
            VirgilSigner(VirgilHash.Algorithm.SHA512).use { virgilSigner ->
                return virgilSigner.verify(data, signature, publicKey.rawKey)
            }
        } catch (e: Exception) {
            throw VerificationException(e)
        }

    }

    /**
     * Verifies the specified signature using original stream and signer's Public key.
     *
     * @param signature
     * Signature bytes for verification.
     * @param stream
     * Original stream for verification.
     * @param publicKey
     * Signer's public key for verification.
     * @return `true` if signature is valid, `false` otherwise.
     * @throws VerificationException
     * if crypto verify operation failed
     */
    @Throws(VerificationException::class)
    fun verifySignature(signature: ByteArray, stream: InputStream, publicKey: VirgilPublicKey): Boolean {
        try {
            VirgilStreamSigner(VirgilHash.Algorithm.SHA512).use { virgilSigner ->
                VirgilStreamDataSource(stream).use { dataSource ->
                    return virgilSigner.verify(dataSource, signature, publicKey.rawKey)
                }
            }
        } catch (e: Exception) {
            throw VerificationException(e)
        }

    }

    @Throws(CryptoException::class)
    private fun computePublicKeyHash(publicKey: ByteArray): ByteArray {
        val publicKeyDER = VirgilKeyPair.publicKeyToDER(publicKey)
        try {
            var hash: ByteArray
            if (isUseSHA256Fingerprints) {
                hash = this.generateHash(publicKeyDER, HashAlgorithm.SHA256)
            } else {
                hash = this.generateHash(publicKeyDER, HashAlgorithm.SHA512)
                hash = Arrays.copyOfRange(hash, 0, 8)
            }
            return hash
        } catch (e: Exception) {
            // This should never happen
            throw CryptoException(e)
        }

    }

    companion object {

        private val UTF8_CHARSET = StandardCharsets.UTF_8
        private val CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE".toByteArray(UTF8_CHARSET)
        private val CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID".toByteArray(UTF8_CHARSET)

        @JvmStatic
        fun createVirgilHash(algorithm: HashAlgorithm): VirgilHash {
            return when (algorithm) {
                HashAlgorithm.MD5 -> VirgilHash(VirgilHash.Algorithm.MD5)
                HashAlgorithm.SHA1 -> VirgilHash(VirgilHash.Algorithm.SHA1)
                HashAlgorithm.SHA224 -> VirgilHash(VirgilHash.Algorithm.SHA224)
                HashAlgorithm.SHA256 -> VirgilHash(VirgilHash.Algorithm.SHA256)
                HashAlgorithm.SHA384 -> VirgilHash(VirgilHash.Algorithm.SHA384)
                HashAlgorithm.SHA512 -> VirgilHash(VirgilHash.Algorithm.SHA512)
                else -> throw IllegalArgumentException()
            }
        }

        @JvmStatic
        fun toVirgilKeyPairType(keysType: KeysType): VirgilKeyPair.Type {
            when (keysType) {
                KeysType.Default -> return VirgilKeyPair.Type.FAST_EC_ED25519
            // RSA with key size less than 2k are unsecured and shouldn't be supported
                KeysType.RSA_2048 -> return VirgilKeyPair.Type.RSA_2048
                KeysType.RSA_3072 -> return VirgilKeyPair.Type.RSA_3072
                KeysType.RSA_4096 -> return VirgilKeyPair.Type.RSA_4096
                KeysType.RSA_8192 -> return VirgilKeyPair.Type.RSA_8192
                KeysType.EC_SECP192R1 -> return VirgilKeyPair.Type.EC_SECP192R1
                KeysType.EC_SECP224R1 -> return VirgilKeyPair.Type.EC_SECP224R1
                KeysType.EC_SECP256R1 -> return VirgilKeyPair.Type.EC_SECP256R1
                KeysType.EC_SECP384R1 -> return VirgilKeyPair.Type.EC_SECP384R1
                KeysType.EC_SECP521R1 -> return VirgilKeyPair.Type.EC_SECP521R1
                KeysType.EC_BP256R1 -> return VirgilKeyPair.Type.EC_BP256R1
                KeysType.EC_BP384R1 -> return VirgilKeyPair.Type.EC_BP384R1
                KeysType.EC_BP512R1 -> return VirgilKeyPair.Type.EC_BP512R1
                KeysType.EC_SECP192K1 -> return VirgilKeyPair.Type.EC_SECP192K1
                KeysType.EC_SECP224K1 -> return VirgilKeyPair.Type.EC_SECP224K1
                KeysType.EC_SECP256K1 -> return VirgilKeyPair.Type.EC_SECP256K1
                KeysType.EC_CURVE25519 -> return VirgilKeyPair.Type.EC_CURVE25519
                KeysType.FAST_EC_X25519 -> return VirgilKeyPair.Type.FAST_EC_X25519
                KeysType.FAST_EC_ED25519 -> return VirgilKeyPair.Type.FAST_EC_ED25519
            }
        }
    }
}
