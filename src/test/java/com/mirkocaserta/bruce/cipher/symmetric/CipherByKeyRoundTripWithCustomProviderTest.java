package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bruce;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import static com.mirkocaserta.bruce.Bruce.cipher;
import static com.mirkocaserta.bruce.Bruce.symmetricKey;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CipherByKeyRoundTripWithCustomProviderTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void roundTrip() {
        Random rng = new SecureRandom();
        byte[] iv = new byte[8];
        rng.nextBytes(iv);
        byte[] key = symmetricKey("DESede", "BC");
        CipherByKey encrypter = Bruce.cipher("DESede", "DESede/CBC/PKCS5Padding", "BC", ENCRYPT);
        CipherByKey decrypter = Bruce.cipher("DESede", "DESede/CBC/PKCS5Padding", "BC", DECRYPT);
        byte[] plainText = "Hi there".getBytes(UTF_8);
        byte[] cypherText = encrypter.encrypt(key, iv, plainText);
        assertNotNull(cypherText);
        byte[] decryptedText = decrypter.encrypt(key, iv, cypherText);
        assertNotNull(decryptedText);
        assertArrayEquals(plainText, decryptedText);
    }

}
