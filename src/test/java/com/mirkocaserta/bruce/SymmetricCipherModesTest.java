package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static org.junit.jupiter.api.Assertions.*;

class SymmetricCipherModesTest {

    // 32 bytes: a multiple of both the 8 and 16 byte block sizes, so NoPadding modes work too
    private static final Bytes PLAINTEXT = Bytes.from("thirty-two bytes of plain text!!");

    @ParameterizedTest
    @EnumSource(SymmetricCipherAlgorithm.class)
    void everyCipherAlgorithmRoundTrips(SymmetricCipherAlgorithm algorithm) {
        String keyAlgorithm = algorithm.algorithmName().split("/")[0];
        Bytes key = Bytes.from(Keystores.symmetricKey(keyAlgorithm, BASE64), BASE64);
        Bytes iv = ivFor(algorithm.algorithmName());

        var encryptor = Bruce.cipherBuilder().key(key).keyAlgorithm(keyAlgorithm).algorithm(algorithm).buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(key).keyAlgorithm(keyAlgorithm).algorithm(algorithm).buildSymmetricDecryptor();

        Bytes ciphertext = encryptor.encrypt(iv, PLAINTEXT);
        assertNotEquals(PLAINTEXT, ciphertext);
        assertEquals(PLAINTEXT, decryptor.decrypt(iv, ciphertext));
    }

    @Test
    void gcmByKeyRoundTrips() {
        Bytes key = aesKey();
        Bytes iv = ivFor("AES/GCM/NoPadding");
        var encryptor = Bruce.cipherBuilder().keyAlgorithm(SymmetricAlgorithm.AES).algorithm(SymmetricCipherAlgorithm.AES_GCM_NO_PADDING).buildSymmetricEncryptorByKey();
        var decryptor = Bruce.cipherBuilder().keyAlgorithm(SymmetricAlgorithm.AES).algorithm(SymmetricCipherAlgorithm.AES_GCM_NO_PADDING).buildSymmetricDecryptorByKey();

        Bytes ciphertext = encryptor.encrypt(key, iv, PLAINTEXT);
        assertEquals(PLAINTEXT, decryptor.decrypt(key, iv, ciphertext));
    }

    @Test
    void gcmAppendsA128BitTag() {
        Bytes key = aesKey();
        var encryptor = Bruce.cipherBuilder().key(key).algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_GCM_NO_PADDING).buildSymmetricEncryptor();
        Bytes ciphertext = encryptor.encrypt(ivFor("AES/GCM/NoPadding"), PLAINTEXT);
        assertEquals(PLAINTEXT.length() + 16, ciphertext.length());
    }

    @Test
    void gcmRejectsTamperedCiphertext() {
        Bytes key = aesKey();
        Bytes iv = ivFor("AES/GCM/NoPadding");
        var encryptor = Bruce.cipherBuilder().key(key).algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_GCM_NO_PADDING).buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(key).algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_GCM_NO_PADDING).buildSymmetricDecryptor();

        byte[] tampered = encryptor.encrypt(iv, PLAINTEXT).asBytes();
        tampered[0] ^= 0x01;

        assertThrows(BruceException.class, () -> decryptor.decrypt(iv, Bytes.from(tampered)));
    }

    @Test
    void ecbIgnoresTheIv() {
        Bytes key = aesKey();
        var encryptor = Bruce.cipherBuilder().key(key).algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_ECB_PKCS5).buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(key).algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_ECB_PKCS5).buildSymmetricDecryptor();

        Bytes ciphertext = encryptor.encrypt(Bytes.from(new byte[16]), PLAINTEXT);
        assertEquals(ciphertext, encryptor.encrypt(Bytes.from(new byte[0]), PLAINTEXT));
        assertEquals(PLAINTEXT, decryptor.decrypt(Bytes.from(new byte[0]), ciphertext));
    }

    @Test
    void transformationWithoutModeUsesProviderDefault() {
        Bytes key = aesKey();
        var encryptor = Bruce.cipherBuilder().key(key).keyAlgorithm("AES").algorithm("AES").buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(key).keyAlgorithm("AES").algorithm("AES").buildSymmetricDecryptor();

        Bytes ciphertext = encryptor.encrypt(Bytes.from(new byte[0]), PLAINTEXT);
        assertEquals(PLAINTEXT, decryptor.decrypt(Bytes.from(new byte[0]), ciphertext));
    }

    private static Bytes aesKey() {
        return Bytes.from(Keystores.symmetricKey("AES", BASE64), BASE64);
    }

    private static Bytes ivFor(String transformation) {
        if (transformation.contains("/GCM/")) {
            return Bytes.from(new byte[12]);
        }
        return Bytes.from(new byte[transformation.startsWith("AES") ? 16 : 8]);
    }
}
