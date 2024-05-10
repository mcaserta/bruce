package com.mirkocaserta.bruce.key;

import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PublicKeyTest {

  @Test
  @DisplayName("loads a public key")
  void publicKeyTest() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    PublicKey publicKey = Bruce.publicKey.with(keystore, "test");
    assertNotNull(publicKey);
    assertEquals("RSA", publicKey.getAlgorithm(), "algorithm");
    assertEquals("X.509", publicKey.getFormat(), "format");
  }

  @Test
  @DisplayName("loading a non existing public key should throw an error")
  void nonExistingKey() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    assertThrows(BruceException.class, () -> Bruce.publicKey.with(keystore, "sgiao belo"));
  }
}
