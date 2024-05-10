package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.Bruce.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class RsaKeyPairWithCustomProviderTest {

  private static final byte[] MESSAGE = "Hello".getBytes(UTF_8);

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void generateAndUse() {
    var keyPair = Bruce.keyPair.with("RSA", "BC", 4096);
    var signer = signer(keyPair.getPrivate(), "RIPEMD160withRSA/ISO9796-2");
    var verifier = verifier(keyPair.getPublic(), "RIPEMD160withRSA/ISO9796-2");
    var signature = signer.sign(MESSAGE);
    assertTrue(verifier.verify(MESSAGE, signature));
  }

  @Test
  void noSuchProvider() {
    assertThrows(BruceException.class, () -> Bruce.keyPair.with("RSA", "sgiao belo", 2048));
  }
}
