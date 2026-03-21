package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.SecureRandom;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

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

        var signer = Bruce.signerBuilder()
                .key(Keystores.privateKey(keystore, "test", "password".toCharArray()))
                .algorithm("SHA512withRSA")
                .build();
        var verifier = Bruce.verifierBuilder()
                .key(Keystores.publicKey(keystore, "test"))
                .algorithm("SHA512withRSA")
                .build();

        Bytes message   = Bytes.from("hello facades");
        Bytes signature = signer.sign(message);
        assertTrue(verifier.verify(message, signature));
    }

    @Test
    void ciphersFacadeRoundTrip() {
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        Bytes iv  = Bytes.from(ivBytes);
        Bytes key = Bytes.from(Keystores.symmetricKey("AES", BASE64), BASE64);

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

        Bytes plaintext  = Bytes.from("Hi there");
        Bytes ciphertext = encryptor.encrypt(iv, plaintext);
        assertEquals("Hi there", decryptor.decrypt(iv, ciphertext).asString());
    }

    @Test
    void digestsAndMacsBuilderRoundTrip() {
        var digester = Bruce.digestBuilder().algorithm("SHA-1").build();
        Bytes digest1 = digester.digest(Bytes.from("message"));
        Bytes digest2 = digester.digest(Bytes.from("message"));
        assertEquals(digest1, digest2);

        KeyStore keystore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var key = Keystores.secretKey(keystore, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(key).algorithm("HmacSHA1").build();

        Bytes first  = mac.get(Bytes.from("Hello there"));
        Bytes second = mac.get(Bytes.from("Hello there"));
        assertEquals(first, second);
    }
}
