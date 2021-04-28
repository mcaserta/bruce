package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class CipherByKeyRoundTripTest {

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

        CipherByKey cipher = cipher(keys, "RSA");

        // Alice writes to Bob
        byte[] aliceMsg01 = "Hello".getBytes(UTF_8);
        byte[] aliceMsg01Encrypted = cipher.encrypt("bob-public", ENCRYPT, aliceMsg01);
        assertNotNull(aliceMsg01Encrypted);

        // Bob decrypts Alice's message
        byte[] aliceMsg01Decrypted = cipher.encrypt("bob-private", DECRYPT, aliceMsg01Encrypted);
        assertNotNull(aliceMsg01Decrypted);
        assertArrayEquals(aliceMsg01, aliceMsg01Decrypted);

        // Bob responds to Alice's message
        byte[] bobMsg01 = "Hey Alice, nice to hear from you.".getBytes(UTF_8);
        byte[] bobMsg01Encrypted = cipher.encrypt("alice-public", ENCRYPT, bobMsg01);
        assertNotNull(bobMsg01Encrypted);

        // Alice decrypts Bob's message
        byte[] bobMsg01Decrypted = cipher.encrypt("alice-private", DECRYPT, bobMsg01Encrypted);
        assertNotNull(bobMsg01Decrypted);
        assertArrayEquals(bobMsg01, bobMsg01Decrypted);

        // Someone writes garbage for Alice
        byte[] garbageForAlice = "sgiao bela".getBytes(UTF_8);
        assertThrows(BruceException.class, () -> cipher.encrypt("alice-private", DECRYPT, garbageForAlice));

        // Someone writes garbage for Bob
        byte[] garbageForBob = "sgiao belo".getBytes(UTF_8);
        assertThrows(BruceException.class, () -> cipher.encrypt("bob-private", DECRYPT, garbageForBob));

        // Using an unregistered key should also throw an exception
        assertThrows(BruceException.class, () -> cipher.encrypt("sgiao-belo", DECRYPT, bobMsg01Encrypted));
    }

}
