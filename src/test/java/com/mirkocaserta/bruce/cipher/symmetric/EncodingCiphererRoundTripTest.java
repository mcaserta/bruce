package com.mirkocaserta.bruce.cipher.symmetric;

import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Bruce.cipherer;
import static com.mirkocaserta.bruce.Bruce.symmetricKey;
import static com.mirkocaserta.bruce.cipher.symmetric.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.symmetric.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class EncodingCiphererRoundTripTest {

    private static final String iv = "AQIDBAUGAQI=";

    @Test
    void roundTrip() {
        String key = symmetricKey("DESede", BASE64);
        EncodingCipherer encrypter = cipherer("DESede", "DESede/CBC/PKCS5Padding", ENCRYPT, UTF_8);
        EncodingCipherer decrypter = cipherer("DESede", "DESede/CBC/PKCS5Padding", DECRYPT, UTF_8);
        String clearText = "Hi there";
        String cypherText = encrypter.encrypt(key, iv, clearText, BASE64);
        assertNotNull(cypherText);
        String decryptedText = decrypter.encrypt(key, iv, cypherText, BASE64);
        assertNotNull(decryptedText);
        assertEquals(clearText, decryptedText);
    }

}