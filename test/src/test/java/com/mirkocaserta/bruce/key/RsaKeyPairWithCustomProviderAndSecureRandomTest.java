package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mirkocaserta.bruce.Bruce;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class RsaKeyPairWithCustomProviderAndSecureRandomTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

  @Test
  void generateAndUse() throws NoSuchAlgorithmException {
    var random = SecureRandom.getInstanceStrong();
    var keyPair = Bruce.keyPair.with("RSA", "BC", 4096, random);
    var signer = signer(keyPair.getPrivate(), "WHIRLPOOLwithRSA/X9.31");
    var verifier = verifier(keyPair.getPublic(), "WHIRLPOOLwithRSA/X9.31");
    var signature = signer.sign(MESSAGE);
    assertTrue(verifier.verify(MESSAGE, signature));
  }
}
