package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

import static com.mirkocaserta.bruce.digest.DigesterConsts.MESSAGE_SHA1;
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
                .encoding(Bruce.Encoding.BASE64)
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(Keystores.publicKey(keystore, "test"))
                .algorithm("SHA512withRSA")
                .encoding(Bruce.Encoding.BASE64)
                .build();

        String message = "hello facades";
        String signature = signer.sign(message);
        assertTrue(verifier.verify(message, signature));
    }

    @Test
    void ciphersFacadeRoundTrip() {
        byte[] ivBytes = new byte[8];
        new SecureRandom().nextBytes(ivBytes);
        String iv = Base64.getEncoder().encodeToString(ivBytes);
        String key = Keystores.symmetricKey("DESede", Bruce.Encoding.BASE64);

        var encrypter = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("DESede")
                .algorithm("DESede/CBC/PKCS5Padding")
                .mode(Mode.ENCRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Bruce.Encoding.BASE64)
                .buildSymmetric();
        var decrypter = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("DESede")
                .algorithm("DESede/CBC/PKCS5Padding")
                .mode(Mode.DECRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Bruce.Encoding.BASE64)
                .buildSymmetric();

        String plainText = "Hi there";
        String cipherText = encrypter.encrypt(iv, plainText);
        String decryptedText = decrypter.encrypt(iv, cipherText);

        assertEquals(plainText, decryptedText);
    }

    @Test
    void digestsAndMacsBuilderRoundTrip() {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(MESSAGE_SHA1, Bruce.digestBuilder().algorithm("SHA1").buildRaw().digest(message));

        KeyStore keystore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var key = Keystores.secretKey(keystore, "hmac", "password".toCharArray());

        String first = Bruce.macBuilder().key(key).algorithm("HmacSHA1").encoding(Bruce.Encoding.BASE64).charset(StandardCharsets.UTF_8).build().get("Hello there");
        String second = Bruce.macBuilder().key(key).algorithm("HmacSHA1").encoding(Bruce.Encoding.BASE64).charset(StandardCharsets.UTF_8).build().get("Hello there");

        assertEquals(first, second);
    }
}

