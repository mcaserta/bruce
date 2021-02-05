package com.mirkocaserta.bruce.cipher.symmetric;

import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Bruce.cipherer;
import static com.mirkocaserta.bruce.Bruce.symmetricKey;
import static com.mirkocaserta.bruce.cipher.symmetric.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.symmetric.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CiphererRoundTripTest {

    private static final byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    @Test
    void roundTrip() {
        byte[] key = symmetricKey("DESede");
        Cipherer encrypter = cipherer("DESede", "DESede/CBC/PKCS5Padding", ENCRYPT);
        Cipherer decrypter = cipherer("DESede", "DESede/CBC/PKCS5Padding", DECRYPT);
        byte[] clearText = "Hi there".getBytes(UTF_8);
        byte[] cypherText = encrypter.encrypt(key, iv, clearText);
        assertNotNull(cypherText);
        byte[] decryptedText = decrypter.encrypt(key, iv, cypherText);
        assertNotNull(decryptedText);
        assertArrayEquals(clearText, decryptedText);
    }

}