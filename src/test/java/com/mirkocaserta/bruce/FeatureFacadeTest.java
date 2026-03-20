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
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureFacadeTest {

    @Test
    void keystoresAndSignaturesFacadeRoundTrip() {
        KeyStore keystore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Bruce.DEFAULT_KEYSTORE_TYPE);
        assertNotNull(keystore);

        var signer = Signatures.signer(
                Keystores.privateKey(keystore, "test", "password".toCharArray()),
                "SHA512withRSA",
                Bruce.Encoding.BASE64
        );
        var verifier = Signatures.verifier(
                Keystores.publicKey(keystore, "test"),
                "SHA512withRSA",
                Bruce.Encoding.BASE64
        );

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

        var encrypter = Ciphers.cipher(
                key,
                "DESede",
                "DESede/CBC/PKCS5Padding",
                Mode.ENCRYPT,
                StandardCharsets.UTF_8,
                Bruce.Encoding.BASE64
        );
        var decrypter = Ciphers.cipher(
                key,
                "DESede",
                "DESede/CBC/PKCS5Padding",
                Mode.DECRYPT,
                StandardCharsets.UTF_8,
                Bruce.Encoding.BASE64
        );

        String plainText = "Hi there";
        String cipherText = encrypter.encrypt(iv, plainText);
        String decryptedText = decrypter.encrypt(iv, cipherText);

        assertEquals(plainText, decryptedText);
    }

    @Test
    void digestsAndMacsFacadesMatchBruceForwarders() {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(MESSAGE_SHA1, Digests.digester("SHA1").digest(message));

        KeyStore keystore = Keystores.keystore("classpath:/keystore.p12", "password".toCharArray(), Bruce.DEFAULT_KEYSTORE_TYPE);
        var key = Keystores.secretKey(keystore, "hmac", "password".toCharArray());

        String first = Macs.mac(key, "HmacSHA1", Bruce.Encoding.BASE64, StandardCharsets.UTF_8).get("Hello there");
        String second = Macs.mac(key, "HmacSHA1", Bruce.Encoding.BASE64, StandardCharsets.UTF_8).get("Hello there");

        assertEquals(first, second);
    }
}

