package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.api.params.KeyStoreParam.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SecretKeyTest {

  @Test
  @DisplayName("loads a secret key")
  void secretKeyTest() throws KeyStoreException {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    final var key = Bruce.secretKey.with(keystore, "hmac", "password".toCharArray());
    assertNotNull(key);
    assertTrue(
        "HmacSHA256".equals(key.getAlgorithm()) || "1.2.840.113549.2.9".equals(key.getAlgorithm()),
        "algorithm");
    assertEquals("RAW", key.getFormat(), "format");
  }

  @Test
  @DisplayName("loading a non existing secret key should throw an error")
  void nonExistingKey() throws KeyStoreException {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    var password = "foo".toCharArray();
    assertThrows(
        BruceException.class, () -> Bruce.secretKey.with(keystore, "sgiao belo", password));
  }

  @Test
  @DisplayName("an exception should be wrapped")
  void exceptionsShouldBeWrapped() {
    KeyStore keystore = mock(KeyStore.class);
    var password = "password".toCharArray();
    assertThrows(BruceException.class, () -> Bruce.secretKey.with(keystore, "hmac", password));
  }
}
