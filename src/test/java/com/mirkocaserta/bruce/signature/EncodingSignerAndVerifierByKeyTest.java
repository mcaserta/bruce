package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EncodingSignerAndVerifierByKeyTest {

  private final KeyStore aliceKeystore =
      keystore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");

  private final KeyStore bobKeystore =
      keystore("classpath:/keystore-bob.p12", "password".toCharArray(), "PKCS12");

  private final EncodingSignerByKey signer =
      signer(
          Map.of(
              "alice",
              privateKey(aliceKeystore, "alice", "password".toCharArray()),
              "bob",
              privateKey(bobKeystore, "bob", "password".toCharArray())),
          "SHA512withRSA",
          BASE64);

  private final EncodingVerifierByKey verifier =
      verifier(
          Map.of("alice", publicKey(aliceKeystore, "alice"), "bob", publicKey(bobKeystore, "bob")),
          "SHA512withRSA",
          BASE64);

  @Test
  void aliceAndBobHaveASignedAndVerifiedConversation() {
    // Alice writes message #01
    String aliceMsg01 = "Hello Bob";
    String aliceSig01 = signer.sign("alice", aliceMsg01);

    // Bob verifies Alice's message #01 and writes his message #01
    assertTrue(verifier.verify("alice", aliceMsg01, aliceSig01));
    String bobMsg01 = "Hey Alice, how you doin'? 😉";
    String bobSig01 = signer.sign("bob", bobMsg01);

    // Alice verifies Bob's message #01 and writes her message #02
    assertTrue(verifier.verify("bob", bobMsg01, bobSig01));
    String aliceMsg02 = "I have a boyfriend 😠";
    String aliceSig02 = signer.sign("alice", aliceMsg02);

    // Bob verifies Alice's message #02 and writes his message #02
    assertTrue(verifier.verify("alice", aliceMsg02, aliceSig02));
    String bobMsg02 = "You know I'm not jealous, come on 🤤";
    String bobSig02 = signer.sign("bob", bobMsg02);

    // Alice verifies Bob's message #02 and writes her message #03
    assertTrue(verifier.verify("bob", bobMsg02, bobSig02));
    String aliceMsg03 = "That's it, Bob: I'm blocking you 🤬";
    String aliceSig03 = signer.sign("alice", aliceMsg03);

    // Bob verifies Alice's message #03 and realizes he's a dirty misogynist
    assertTrue(verifier.verify("alice", aliceMsg03, aliceSig03));

    // Hopefully at this point Bob is in India. He has found his true self
    // and is now treating women with love and respect.
  }
}
