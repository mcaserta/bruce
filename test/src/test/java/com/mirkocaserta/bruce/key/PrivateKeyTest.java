package com.mirkocaserta.bruce.key;

import static com.mirkocaserta.bruce.api.params.KeyStoreParam.location;
import static com.mirkocaserta.bruce.api.params.KeyStoreParam.password;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PrivateKeyTest {

  @Test
  @DisplayName("loads a private key")
  void privateKeyTest() throws KeyStoreException {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    final var privateKey = Bruce.privateKey.with(keystore, "test", "password".toCharArray());
    assertNotNull(privateKey);
    assertEquals("RSA", privateKey.getAlgorithm(), "algorithm");
    assertEquals("PKCS#8", privateKey.getFormat(), "format");
  }

  @Test
  @DisplayName("loading a non existing private key should throw an error")
  void nonExistingKey() throws KeyStoreException {
    final var keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
    final var password = "foo".toCharArray();
    assertThrows(
        BruceException.class, () -> Bruce.privateKey.with(keystore, "sgiao belo", password));
  }

  @Test
  @DisplayName("an exception thrown in getPrivateKey should be wrapped")
  void exceptionsShouldBeWrapped() {
    var keystore = mock(KeyStore.class);
    var password = "password".toCharArray();
    assertThrows(BruceException.class, () -> Bruce.privateKey.with(keystore, "test", password));
  }
}
