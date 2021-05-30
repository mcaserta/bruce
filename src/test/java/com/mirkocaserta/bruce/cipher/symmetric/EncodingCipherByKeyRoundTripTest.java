package com.mirkocaserta.bruce.cipher.symmetric;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class EncodingCipherByKeyRoundTripTest {

    @Test
    void roundTrip() {
        Random rng = new SecureRandom();
        byte[] ivBA = new byte[8];
        rng.nextBytes(ivBA);
        String iv = Base64.getEncoder().encodeToString(ivBA);
        String key = symmetricKey("DESede", BASE64);
        EncodingCipherByKey encrypter = cipherByKey("DESede", "DESede/CBC/PKCS5Padding", ENCRYPT, UTF_8);
        EncodingCipherByKey decrypter = cipherByKey("DESede", "DESede/CBC/PKCS5Padding", DECRYPT, UTF_8);
        String plainText = "Hi there";
        String cypherText = encrypter.encrypt(key, iv, plainText, BASE64);
        assertNotNull(cypherText);
        String decryptedText = decrypter.encrypt(key, iv, cypherText, BASE64);
        assertNotNull(decryptedText);
        assertEquals(plainText, decryptedText);
    }

}
