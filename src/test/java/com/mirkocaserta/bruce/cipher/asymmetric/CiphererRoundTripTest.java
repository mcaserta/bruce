package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.Mode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class CiphererRoundTripTest {

    private final KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password", "PKCS12");
    private final KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password", "PKCS12");
    private final Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password");
    private final Key bobPrivateKey = privateKey(bobKeystore, "bob", "password");
    private final Key alicePublicKey = publicKey(aliceKeystore, "alice");
    private final Key bobPublicKey = publicKey(bobKeystore, "bob");

    @Test
    void roundTrip() {
        Cipherer encryptForAlice = cipherer(alicePublicKey, "RSA", ENCRYPT);
        Cipherer decryptForAlice = cipherer(alicePrivateKey, "RSA", DECRYPT);
        Cipherer encryptForBob = cipherer(bobPublicKey, "RSA", ENCRYPT);
        Cipherer decryptForBob = cipherer(bobPrivateKey, "RSA", DECRYPT);

        // Alice writes to Bob
        byte[] aliceMsg01 = "Hello".getBytes(UTF_8);
        byte[] aliceMsg01Encrypted = encryptForBob.encrypt(aliceMsg01);
        assertNotNull(aliceMsg01Encrypted);

        // Bob decrypts Alice's message
        byte[] aliceMsg01Decrypted = decryptForBob.encrypt(aliceMsg01Encrypted);
        assertNotNull(aliceMsg01Decrypted);
        assertArrayEquals(aliceMsg01, aliceMsg01Decrypted);

        // Bob responds to Alice's message
        byte[] bobMsg01 = "Hey Alice, nice to hear from you.".getBytes(UTF_8);
        byte[] bobMsg01Encrypted = encryptForAlice.encrypt(bobMsg01);
        assertNotNull(bobMsg01Encrypted);

        // Alice decrypts Bob's message
        byte[] bobMsg01Decrypted = decryptForAlice.encrypt(bobMsg01Encrypted);
        assertNotNull(bobMsg01Decrypted);
        assertArrayEquals(bobMsg01, bobMsg01Decrypted);

        // Someone writes garbage for Alice
        assertThrows(BruceException.class, () -> decryptForAlice.encrypt("sgiao bela".getBytes(UTF_8)));

        // Someone writes garbage for Bob
        assertThrows(BruceException.class, () -> decryptForBob.encrypt("sgiao belo".getBytes(UTF_8)));
    }

}