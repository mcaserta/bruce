package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.Mode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SymmetricCipherOperationsTest {

    @Test
    void modeCannotBeNull() {
        assertThrows(BruceException.class,
                () -> SymmetricCipherOperations.createCipherByKey("AES", "AES/CBC/PKCS5Padding", (Mode) null));
        assertThrows(BruceException.class,
                () -> SymmetricCipherOperations.createCipherByKey("AES", "AES/CBC/PKCS5Padding", "", null));
    }

    @Test
    void wrapsCipherFailures() {
        byte[] key = new byte[]{1};
        byte[] iv = new byte[16];
        byte[] message = "payload".getBytes(StandardCharsets.UTF_8);
        var cipher = SymmetricCipherOperations.createCipherByKey("AES", "AES/CBC/PKCS5Padding", Mode.ENCRYPT);

        BruceException exception = assertThrows(BruceException.class, () -> cipher.encrypt(key, iv, message));
        assertTrue(exception.getMessage().contains("error encrypting/decrypting message"));
    }

    @Test
    void encodingAndRawOverloadsWork() {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        var enc = Base64.getEncoder();
        String encodedKey = enc.encodeToString(key);
        String encodedIv = enc.encodeToString(iv);

        var encrypter = SymmetricCipherOperations.createEncodingCipher(
                encodedKey,
                "AES",
                "AES/CBC/PKCS5Padding",
                Mode.ENCRYPT,
                StandardCharsets.UTF_8,
                Bruce.Encoding.BASE64);
        var decrypter = SymmetricCipherOperations.createEncodingCipherByKey(
                "AES",
                "AES/CBC/PKCS5Padding",
                Mode.DECRYPT,
                StandardCharsets.UTF_8);

        String cipherText = encrypter.encrypt(encodedIv, "hello-symmetric-overloads");
        String plainText = decrypter.encrypt(encodedKey, encodedIv, cipherText, Bruce.Encoding.BASE64);

        var rawEncrypter = SymmetricCipherOperations.createCipher(key, "AES", "AES/CBC/PKCS5Padding", Mode.ENCRYPT);
        var rawDecrypter = SymmetricCipherOperations.createCipher(key, "AES", "AES/CBC/PKCS5Padding", Mode.DECRYPT);
        byte[] rawCipher = rawEncrypter.encrypt(iv, "raw".getBytes(StandardCharsets.UTF_8));
        byte[] rawPlain = rawDecrypter.encrypt(iv, rawCipher);

        assertTrue(plainText.startsWith("hello-symmetric-overloads"));
        assertArrayEquals("raw".getBytes(StandardCharsets.UTF_8), rawPlain);
    }
}

