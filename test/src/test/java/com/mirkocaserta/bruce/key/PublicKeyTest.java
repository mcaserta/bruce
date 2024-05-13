package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.api.KeyStoreParam.location;
import static com.mirkocaserta.bruce.api.KeyStoreParam.password;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStoreException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PublicKeyTest {

  @Test
  @DisplayName("loads a public key")
  void publicKeyTest() throws KeyStoreException {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    final var publicKey = Bruce.publicKey.with(keystore, "test");
    assertNotNull(publicKey);
    assertEquals("RSA", publicKey.getAlgorithm(), "algorithm");
    assertEquals("X.509", publicKey.getFormat(), "format");
  }

  @Test
  @DisplayName("loading a non existing public key should throw an error")
  void nonExistingKey() throws KeyStoreException {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    assertThrows(BruceException.class, () -> Bruce.publicKey.with(keystore, "sgiao belo"));
  }
}
