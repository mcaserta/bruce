package com.mirkocaserta.bruce.cipher.symmetric;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Random;

import static com.mirkocaserta.bruce.Bruce.cipher;
import static com.mirkocaserta.bruce.Bruce.symmetricKey;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CipherByKeyRoundTripTest {

    @Test
    void roundTrip() {
        Random rng = new SecureRandom();
        byte[] iv = new byte[8];
        rng.nextBytes(iv);
        byte[] key = symmetricKey("DESede");
        CipherByKey encrypter = cipher("DESede", "DESede/CBC/PKCS5Padding", ENCRYPT);
        CipherByKey decrypter = cipher("DESede", "DESede/CBC/PKCS5Padding", DECRYPT);
        byte[] plainText = "Hi there".getBytes(UTF_8);
        byte[] cypherText = encrypter.encrypt(key, iv, plainText);
        assertNotNull(cypherText);
        byte[] decryptedText = decrypter.encrypt(key, iv, cypherText);
        assertNotNull(decryptedText);
        assertArrayEquals(plainText, decryptedText);
    }

}
