package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnifiedApiRoundTripTest {

    @Test
    void digesterSupportsMixedRepresentations() {
        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();
        byte[] raw = digester.digest("payload".getBytes(StandardCharsets.UTF_8));
        String encoded = digester.digestToString("payload");

        assertArrayEquals(raw, Base64.getDecoder().decode(encoded));
        assertFalse(digester.digestToString("payload", Bruce.Encoding.HEX).isBlank());
    }

    @Test
    void macSupportsMixedRepresentations() {
        KeyStore keyStore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var secretKey = Keystores.secretKey(keyStore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(secretKey).algorithm("HmacSHA1").build();

        byte[] raw = mac.get("payload");
        String encoded = mac.getToString("payload");

        assertArrayEquals(raw, Base64.getDecoder().decode(encoded));
    }

    @Test
    void signatureSupportsBytesToEncodedStringVerification() {
        KeyPair keyPair = Keystores.keyPair("RSA", 2048);
        var signer = Bruce.signerBuilder().key(keyPair.getPrivate()).algorithm("SHA256withRSA").build();
        var verifier = Bruce.verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withRSA").build();

        byte[] message = "mixed-signature".getBytes(StandardCharsets.UTF_8);
        String signature = signer.signToString(message);

        assertTrue(verifier.verify(message, signature));
    }

    @Test
    void symmetricCipherSupportsStringAndBytesAcrossDirections() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        String encodedIv = Base64.getEncoder().encodeToString(iv);
        String key = Keystores.symmetricKey("AES", Bruce.Encoding.BASE64);

        var encryptor = Bruce.cipherBuilder().key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding").buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding").buildSymmetricDecryptor();

        String cipherText = encryptor.encryptToString(encodedIv, "clear text");
        byte[] plainBytes = decryptor.decrypt(encodedIv, cipherText);

        assertEquals("clear text", new String(plainBytes, StandardCharsets.UTF_8));
    }

    @Test
    void asymmetricCipherAndByKeySupportMixedRepresentations() {
        KeyPair keyPair = Keystores.keyPair("RSA", 2048);

        var encryptor = Bruce.cipherBuilder().key(keyPair.getPublic()).algorithm("RSA").buildAsymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder().key(keyPair.getPrivate()).algorithm("RSA").buildAsymmetricDecryptor();

        byte[] cipherBytes = encryptor.encrypt("hello asymmetric");
        String clearText = decryptor.decryptToString(cipherBytes);
        assertEquals("hello asymmetric", clearText);

        var encryptorByKey = Bruce.cipherBuilder().keys(Map.of("pub", keyPair.getPublic())).algorithm("RSA").buildAsymmetricEncryptorByKey();
        var decryptorByKey = Bruce.cipherBuilder().keys(Map.of("priv", keyPair.getPrivate())).algorithm("RSA").buildAsymmetricDecryptorByKey();
        String cipherText = encryptorByKey.encryptToString("pub", "hello by key");
        assertEquals("hello by key", decryptorByKey.decryptToString("priv", cipherText));
    }
}

