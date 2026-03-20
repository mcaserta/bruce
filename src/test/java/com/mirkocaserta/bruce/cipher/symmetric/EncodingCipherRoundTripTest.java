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

class EncodingCipherRoundTripTest {

    @Test
    void roundTrip() {
        Random rng = new SecureRandom();
        byte[] ivBA = new byte[8];
        rng.nextBytes(ivBA);
        String iv = Base64.getEncoder().encodeToString(ivBA);
        String key = symmetricKey("DESede", BASE64);
        EncodingCipher encrypter = cipherBuilder().key(key).keyAlgorithm("DESede").algorithm("DESede/CBC/PKCS5Padding").mode(ENCRYPT).charset(UTF_8).encoding(BASE64).buildSymmetric();
        EncodingCipher decrypter = cipherBuilder().key(key).keyAlgorithm("DESede").algorithm("DESede/CBC/PKCS5Padding").mode(DECRYPT).charset(UTF_8).encoding(BASE64).buildSymmetric();
        String plainText = "Hi there";
        String cypherText = encrypter.encrypt(iv, plainText);
        assertNotNull(cypherText);
        String decryptedText = decrypter.encrypt(iv, cypherText);
        assertNotNull(decryptedText);
        assertEquals(plainText, decryptedText);
    }

}
