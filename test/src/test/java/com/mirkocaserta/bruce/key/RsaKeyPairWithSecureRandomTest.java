package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mirkocaserta.bruce.Bruce;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class RsaKeyPairWithSecureRandomTest {

  private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

  @Test
  void generateAndUse() throws NoSuchAlgorithmException {
    var random = SecureRandom.getInstanceStrong();
    random.setSeed(new byte[] {0, 1, 2, 3, 4, 5});
    var keyPair = Bruce.keyPair.with("RSA", 4096, random);
    var signer = signer(keyPair.getPrivate(), "SHA512withRSA");
    var verifier = verifier(keyPair.getPublic(), "SHA512withRSA");
    var signature = signer.sign(MESSAGE);
    assertTrue(verifier.verify(MESSAGE, signature));
  }
}
