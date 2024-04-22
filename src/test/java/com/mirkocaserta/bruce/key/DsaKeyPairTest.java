package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DsaKeyPairTest {

  private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

  @Test
  void generateAndUse() {
    var keyPair = keyPair("DSA", 2048);
    var signer = signer(keyPair.getPrivate(), "SHA256withDSA");
    var verifier = verifier(keyPair.getPublic(), "SHA256withDSA");
    var signature = signer.sign(MESSAGE);
    assertTrue(verifier.verify(MESSAGE, signature));
  }
}
