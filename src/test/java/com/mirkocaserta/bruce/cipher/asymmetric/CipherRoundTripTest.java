package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyStore;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class CipherRoundTripTest {

    private final KeyStore aliceKeystore = keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
    private final KeyStore bobKeystore = keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");
    private final Key alicePrivateKey = privateKey(aliceKeystore, "alice", "password".toCharArray());
    private final Key bobPrivateKey = privateKey(bobKeystore, "bob", "password".toCharArray());
    private final Key alicePublicKey = publicKey(aliceKeystore, "alice");
    private final Key bobPublicKey = publicKey(bobKeystore, "bob");

    @Test
    void roundTrip() {
        Cipher encryptForAlice = cipher(alicePublicKey, "RSA", ENCRYPT);
        Cipher decryptForAlice = cipher(alicePrivateKey, "RSA", DECRYPT);
        Cipher encryptForBob = cipher(bobPublicKey, "RSA", ENCRYPT);
        Cipher decryptForBob = cipher(bobPrivateKey, "RSA", DECRYPT);

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
        byte[] garbageForAlice = "sgiao bela".getBytes(UTF_8);
        assertThrows(BruceException.class, () -> decryptForAlice.encrypt(garbageForAlice));

        // Someone writes garbage for Bob
        byte[] garbageForBob = "sgiao belo".getBytes(UTF_8);
        assertThrows(BruceException.class, () -> decryptForBob.encrypt(garbageForBob));
    }

}
