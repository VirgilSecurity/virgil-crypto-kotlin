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
package com.virgilsecurity.amiImplementation;

import com.virgilsecurity.apiImplementation.VirgilCrypto;
import com.virgilsecurity.apiImplementation.VirgilKeyPair;
import com.virgilsecurity.apiImplementation.VirgilPrivateKey;
import com.virgilsecurity.apiImplementation.VirgilPublicKey;
import crypto.HashAlgorithm;
import crypto.KeysType;
import exception.CryptoException;
import exception.SigningException;
import exception.VirgilException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.*;
import java.util.*;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link VirgilCrypto}
 *
 * @author Andrii Iakovenko
 *
 */
@RunWith(Parameterized.class)
public class VirgilCryptoTest {

    private static final String TEXT = "This text is used for unit tests";
    private static final String PASSWORD = "ThisIsPassWoRd2016";
    private static final byte[] INVALID_SIGNATURE = new byte[] { 48, 88, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 2,
            5, 0, 4, 71, 48, 69, 2, 33, 0, -108, -6, -82, 29, -38, 103, -13, 42, 101, 76, -34, -53, -96, -70, 85, 80, 0,
            88, 77, 48, 9, -100, 81, 39, -51, -125, -102, -107, -108, 14, -88, 7, 2, 32, 13, -71, -99, 8, -69, -77, 30,
            98, 20, -25, 60, 125, -19, 67, 12, -30, 65, 93, -29, -92, -58, -91, 91, 50, -111, -79, 50, -123, -39, 36,
            48, -20 };

    private KeysType keysType;
    private VirgilCrypto crypto;

    @Parameters(name = "keyType={0}")
    public static KeysType[] params() {
        Set<KeysType> values = new HashSet<>(Arrays.asList(KeysType.values()));
        // Skip RSA test because they are too slow
        values.remove(KeysType.RSA_3072);
        values.remove(KeysType.RSA_4096);
        values.remove(KeysType.RSA_8192);
        return values.toArray(new KeysType[0]);
    }

    /**
     * Create new instance of {@link VirgilCryptoTest}.
     */
    public VirgilCryptoTest(KeysType keysType) {
        this.keysType = keysType;
    }

    @Before
    public void setup() {
        crypto = new VirgilCrypto(this.keysType);
    }

    @Test(expected = IllegalArgumentException.class)
    public void computeHash() throws CryptoException {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            byte[] hash = crypto.generateHash(null, algorithm);

            assertNotNull(hash);
            assertTrue(hash.length > 0);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void computeHash_nullData() throws CryptoException {
        crypto.generateHash(null, HashAlgorithm.MD5);
    }

    @Test
    public void decrypt() throws VirgilException {
        List<VirgilPrivateKey> privateKeys = new ArrayList<>();
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            VirgilKeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
        for (VirgilPrivateKey privateKey : privateKeys) {
            byte[] decrypted = crypto.decrypt(encrypted, privateKey);
            assertArrayEquals(TEXT.getBytes(), decrypted);
        }
    }

    @Test
    public void decrypt_stream() throws IOException, VirgilException {
        List<VirgilPrivateKey> privateKeys = new ArrayList<>();
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 1; i++) {
            VirgilKeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
        try (InputStream is = new ByteArrayInputStream(encrypted);
                ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            for (VirgilPrivateKey privateKey : privateKeys) {
                crypto.decrypt(is, os, privateKey);

                byte[] decrypted = os.toByteArray();

                assertArrayEquals(TEXT.getBytes(), decrypted);
            }
        }
    }

    @Test
    @Ignore
    public void decryptThenVerify() {

    }

    @Test
    public void encrypt() throws VirgilException {
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);

        assertNotNull(encrypted);
    }

    @Test
    public void encrypt_noRecipients_success() throws VirgilException {
        @SuppressWarnings("unchecked")
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), Collections.EMPTY_LIST);

        assertNotNull(encrypted);
    }

    @Test
    public void encrypt_stream() throws IOException, CryptoException {
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        try (OutputStream os = new ByteArrayOutputStream()) {
            crypto.encrypt(new ByteArrayInputStream(TEXT.getBytes()), os, recipients);
        }
    }

    @Test
    public void exportPrivateKey_noPassword() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey(), null);

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    @Test
    public void exportPrivateKey_withPassword() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    @Test
    public void exportPublicKey() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();

        byte[] key = crypto.exportPublicKey(keyPair.getPublicKey());

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    @Test
    public void generateKeys() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();

        assertNotNull(keyPair);

        VirgilPublicKey publicKey = keyPair.getPublicKey();
        assertNotNull(publicKey);
        assertNotNull(publicKey.getIdentifier());
        assertNotNull(publicKey.getRawKey());

        VirgilPrivateKey privateKey = keyPair.getPrivateKey();
        assertNotNull(privateKey);
        assertNotNull(privateKey.getIdentifier());
        assertNotNull(privateKey.getRawKey());
    }

    @Test
    public void generateSignature() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void generateSignature_nullData() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();
        crypto.generateSignature((byte[]) null, keyPair.getPrivateKey());
    }

    @Test(expected = IllegalArgumentException.class)
    public void generateSignature_nullPrivateKey() throws CryptoException {
        crypto.generateSignature(TEXT.getBytes(), null);
    }

    @Test
    public void generateSignature_stream() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    @Test(expected = IllegalArgumentException.class)
    public void generateSignature_stream_nullPrivateKey() throws SigningException {
        crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void generateSignature_stream_nullStream() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();
        crypto.generateSignature((InputStream) null, keyPair.getPrivateKey());
    }

    @Test
    public void importPrivateKey_noPassword() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), null);

        VirgilPrivateKey importedKey = crypto.importPrivateKey(keyData, null);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getIdentifier());
        assertNotNull(importedKey.getRawKey());
        assertArrayEquals(keyPair.getPrivateKey().getIdentifier(), importedKey.getIdentifier());
        assertArrayEquals(keyPair.getPrivateKey().getRawKey(), importedKey.getRawKey());
    }

    @Test
    public void importPrivateKey_withPassword() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        VirgilPrivateKey importedKey = crypto.importPrivateKey(keyData, PASSWORD);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getIdentifier());
        assertNotNull(importedKey.getRawKey());
        assertArrayEquals(keyPair.getPrivateKey().getIdentifier(), importedKey.getIdentifier());
        assertArrayEquals(keyPair.getPrivateKey().getRawKey(), importedKey.getRawKey());
    }

    @Test(expected = CryptoException.class)
    public void importPrivateKey_withWrongPassword() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        crypto.importPrivateKey(keyData, PASSWORD + "1");
    }

    @Test
    public void importPublicKey() throws CryptoException {
        VirgilKeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPublicKey(keyPair.getPublicKey());
        VirgilPublicKey publicKey = crypto.importPublicKey(keyData);

        assertNotNull(publicKey);
        assertNotNull(publicKey.getIdentifier());
        assertNotNull(publicKey.getRawKey());
        assertArrayEquals(keyPair.getPublicKey().getIdentifier(), publicKey.getIdentifier());
        assertArrayEquals(keyPair.getPublicKey().getRawKey(), publicKey.getRawKey());
    }

    @Test
    public void sign_stream_compareToByteArraySign() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        byte[] streamSignature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()),
                keyPair.getPrivateKey());

        assertNotNull(signature);
        assertNotNull(streamSignature);
        assertArrayEquals(signature, streamSignature);
    }

    @Test
    @Ignore
    public void signThenEncrypt() {

    }

    @Test
    public void toVirgilKeyPairType() {
        for (KeysType keysType : KeysType.values()) {
            com.virgilsecurity.crypto.VirgilKeyPair.Type type = VirgilCrypto.toVirgilKeyPairType(keysType);
            assertNotNull(type);
        }
    }

    @Test
    public void verifySignature() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(signature, TEXT.getBytes(), keyPair.getPublicKey());

        assertTrue(valid);
    }

    @Test
    public void verifySignature_invalidSignature() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(INVALID_SIGNATURE, TEXT.getBytes(), keyPair.getPublicKey());

        assertFalse(valid);
    }

    @Test
    public void verifySignature_stream() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(signature, new ByteArrayInputStream(TEXT.getBytes()),
                keyPair.getPublicKey());

        assertTrue(valid);
    }

    @Test
    public void verifySignature_stream_invalidSignature() throws CryptoException {
        if (KeysType.FAST_EC_X25519 == this.keysType) {
            return;
        }
        VirgilKeyPair keyPair = crypto.generateKeys();
        crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(INVALID_SIGNATURE, new ByteArrayInputStream(TEXT.getBytes()),
                keyPair.getPublicKey());

        assertFalse(valid);
    }
}
