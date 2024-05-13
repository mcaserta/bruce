package com.mirkocaserta.bruce.signature;

import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.api.KeyStoreParam.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.PrivateKey;
import org.junit.jupiter.api.Test;

class SignerAndVerifierExceptionTest {

  @Test
  void noSuchAlgorithm() {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    final PrivateKey privateKey = Bruce.privateKey.with(keystore, "test", "password".toCharArray());
    assertThrows(BruceException.class, () -> signer(privateKey, "FOO512withBAR"));
  }

  @Test
  void invalidKey() {
    PrivateKey privateKey = mock(PrivateKey.class);
    assertThrows(BruceException.class, () -> signer(privateKey, "SHA512withRSA"));
  }
}
