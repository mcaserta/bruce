package com.mirkocaserta.bruce.cipher.symmetric;

import static com.mirkocaserta.bruce.Bruce.symmetricKey;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.SecureRandom;
import java.util.Random;

import org.junit.jupiter.api.Test;

import com.mirkocaserta.bruce.Bruce;

class CipherRoundTripTest {

    @Test
    void roundTrip() {
        Random rng = new SecureRandom();
        byte[] iv = new byte[8];
        rng.nextBytes(iv);
        byte[] key = symmetricKey("DESede");
        Cipher encrypter = Bruce.cipher(key, "DESede", "DESede/CBC/PKCS5Padding", ENCRYPT);
        Cipher decrypter = Bruce.cipher(key, "DESede", "DESede/CBC/PKCS5Padding", DECRYPT);
        byte[] plainText = "Hi there".getBytes(UTF_8);
        byte[] cypherText = encrypter.encrypt(iv, plainText);
        assertNotNull(cypherText);
        byte[] decryptedText = decrypter.encrypt(iv, cypherText);
        assertNotNull(decryptedText);
        assertArrayEquals(plainText, decryptedText);
    }

}
