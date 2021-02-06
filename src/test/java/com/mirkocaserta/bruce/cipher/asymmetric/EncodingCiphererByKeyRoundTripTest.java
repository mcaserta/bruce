package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class EncodingCiphererByKeyRoundTripTest {

    private final KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password", "PKCS12");
    private final KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password", "PKCS12");
    private final Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password");
    private final Key bobPrivateKey = privateKey(bobKeystore, "bob", "password");
    private final Key alicePublicKey = publicKey(aliceKeystore, "alice");
    private final Key bobPublicKey = publicKey(bobKeystore, "bob");

    @Test
    void roundTrip() {
        Map<String, Key> keys = new HashMap<>();
        keys.put("alice-public", alicePublicKey);
        keys.put("alice-private", alicePrivateKey);
        keys.put("bob-public", bobPublicKey);
        keys.put("bob-private", bobPrivateKey);

        EncodingCiphererByKey cipherer = cipherer(keys, "RSA", BASE64, UTF_8);

        // Alice writes to Bob
        String aliceMsg01 = "Hello";
        String aliceMsg01Encrypted = cipherer.encrypt("bob-public", ENCRYPT, aliceMsg01);
        assertNotNull(aliceMsg01Encrypted);

        // Bob decrypts Alice's message
        String aliceMsg01Decrypted = cipherer.encrypt("bob-private", DECRYPT, aliceMsg01Encrypted);
        assertNotNull(aliceMsg01Decrypted);
        assertEquals(aliceMsg01, aliceMsg01Decrypted);

        // Bob responds to Alice's message
        String bobMsg01 = "Hey Alice, nice to hear from you.";
        String bobMsg01Encrypted = cipherer.encrypt("alice-public", ENCRYPT, bobMsg01);
        assertNotNull(bobMsg01Encrypted);

        // Alice decrypts Bob's message
        String bobMsg01Decrypted = cipherer.encrypt("alice-private", DECRYPT, bobMsg01Encrypted);
        assertNotNull(bobMsg01Decrypted);
        assertEquals(bobMsg01, bobMsg01Decrypted);

        // Someone writes garbage for Alice
        assertThrows(BruceException.class, () -> cipherer.encrypt("alice-private", DECRYPT, "sgiao bela"));

        // Someone writes garbage for Bob
        assertThrows(BruceException.class, () -> cipherer.encrypt("bob-private", DECRYPT, "sgiao belo"));

        // Using an unregistered key should also throw an exception
        assertThrows(BruceException.class, () -> cipherer.encrypt("sgiao-belo", DECRYPT, bobMsg01Encrypted));
    }

}