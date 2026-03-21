package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureFacadeTest {

    @Test
    void featureFacadesExposeBuilders() {
        assertNotNull(Ciphers.builder());
        assertNotNull(Digests.builder());
        assertNotNull(Macs.builder());
        assertNotNull(Signatures.signerBuilder());
        assertNotNull(Signatures.verifierBuilder());

        assertNotSame(Ciphers.builder(), Ciphers.builder());
        assertNotSame(Digests.builder(), Digests.builder());
    }

    @Test
    void keystoresAndSignaturesFacadeRoundTrip() {
        KeyStore keystore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        assertNotNull(keystore);

        var signer = Bruce.signerBuilder()
                .key(Keystores.privateKey(keystore, "test", "password".toCharArray()))
                .algorithm("SHA512withRSA")
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(Keystores.publicKey(keystore, "test"))
                .algorithm("SHA512withRSA")
                .build();

        byte[] message = "hello facades".getBytes(StandardCharsets.UTF_8);
        String signature = signer.signToString(message);
        assertTrue(verifier.verify(message, signature));
    }

    @Test
    void ciphersFacadeRoundTrip() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        String key = Keystores.symmetricKey("AES", Bruce.Encoding.BASE64);

        var encryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptor();
        var decryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricDecryptor();

        String plainText = "Hi there";
        String cipherText = encryptor.encryptToString(iv, plainText);
        String decryptedText = decryptor.decryptToString(iv, cipherText);

        assertEquals(plainText, decryptedText);
    }

    @Test
    void digestsAndMacsBuilderRoundTrip() {
        var digester = Bruce.digestBuilder().algorithm("SHA-1").build();
        byte[] digest = digester.digest("message");
        assertArrayEquals(digest, Base64.getDecoder().decode(digester.digestToString("message")));

        KeyStore keystore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var key = Keystores.secretKey(keystore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(key).algorithm("HmacSHA1").build();

        String first = mac.getToString("Hello there");
        String second = mac.getToString("Hello there");

        assertEquals(first, second);
    }
}
