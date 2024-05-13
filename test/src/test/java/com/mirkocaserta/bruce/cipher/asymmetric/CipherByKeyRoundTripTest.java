package com.mirkocaserta.bruce.cipher.asymmetric;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.api.KeyStoreParam.*;
import static com.mirkocaserta.bruce.cipher.Mode.DECRYPT;
import static com.mirkocaserta.bruce.cipher.Mode.ENCRYPT;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.Key;
import java.security.KeyStore;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CipherByKeyRoundTripTest {

  private final KeyStore aliceKeystore =
      Bruce.keystore.with(
          location("classpath:/keystore-alice.p12"),
          password("password".toCharArray()),
          type("PKCS12"));
  private final KeyStore bobKeystore =
      Bruce.keystore.with(
          location("classpath:/keystore-bob.p12"),
          password("password".toCharArray()),
          type("PKCS12"));
  private final Key alicePrivateKey =
      Bruce.privateKey.with(aliceKeystore, "alice", "password".toCharArray());
  private final Key bobPrivateKey =
      Bruce.privateKey.with(bobKeystore, "bob", "password".toCharArray());
  private final Key alicePublicKey = Bruce.publicKey.with(aliceKeystore, "alice");
  private final Key bobPublicKey = Bruce.publicKey.with(bobKeystore, "bob");

  @Test
  void roundTrip() {
    Map<String, Key> keys =
        Map.of(
            "alice-public", alicePublicKey,
            "alice-private", alicePrivateKey,
            "bob-public", bobPublicKey,
            "bob-private", bobPrivateKey);

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
    assertThrows(
        BruceException.class, () -> cipher.encrypt("alice-private", DECRYPT, garbageForAlice));

    // Someone writes garbage for Bob
    byte[] garbageForBob = "sgiao belo".getBytes(UTF_8);
    assertThrows(BruceException.class, () -> cipher.encrypt("bob-private", DECRYPT, garbageForBob));

    // Using an unregistered key should also throw an exception
    assertThrows(
        BruceException.class, () -> cipher.encrypt("sgiao-belo", DECRYPT, bobMsg01Encrypted));
  }
}
