package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

class RsaKeyPairTest {

  private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

  @Test
  void generateAndUse() {
    var keyPair = keyPair("RSA", 4096);
    var signer = signer(keyPair.getPrivate(), "SHA512withRSA");
    var verifier = verifier(keyPair.getPublic(), "SHA512withRSA");
    var signature = signer.sign(MESSAGE);
    assertTrue(verifier.verify(MESSAGE, signature));
  }

  @Test
  void noSuchAlgorithm() {
    assertThrows(BruceException.class, () -> keyPair("XXX", 2048));
  }

  @Test
  void invalidKeySize() {
    assertThrows(BruceException.class, () -> keyPair("RSA", 23));
  }
}
