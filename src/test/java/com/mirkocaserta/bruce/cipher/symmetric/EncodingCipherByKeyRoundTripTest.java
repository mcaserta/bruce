package com.mirkocaserta.bruce.cipher.symmetric;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

import static com.mirkocaserta.bruce.Bruce.cipherBuilder;
import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Keystores.symmetricKey;
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
        EncodingCipherByKey encrypter = cipherBuilder().keyAlgorithm("DESede").algorithm("DESede/CBC/PKCS5Padding").mode(ENCRYPT).charset(UTF_8).buildSymmetricByKey();
        EncodingCipherByKey decrypter = cipherBuilder().keyAlgorithm("DESede").algorithm("DESede/CBC/PKCS5Padding").mode(DECRYPT).charset(UTF_8).buildSymmetricByKey();
        String plainText = "Hi there";
        String cypherText = encrypter.encrypt(key, iv, plainText, BASE64);
        assertNotNull(cypherText);
        String decryptedText = decrypter.encrypt(key, iv, cypherText, BASE64);
        assertNotNull(decryptedText);
        assertEquals(plainText, decryptedText);
    }

}
