package com.mirkocaserta.bruce.keystore;

import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KeystoreTest {

  @DisplayName("loads a with from the classpath and the filesystem")
  @ParameterizedTest
  @ValueSource(
      strings = {
        "classpath:/keystore.p12",
        "file:src/test/resources/keystore.p12",
        "src/test/resources/keystore.p12"
      })
  void classpathKeystore(String location) throws KeyStoreException {
    KeyStore keystore = Bruce.keystore.with(location, "password".toCharArray());
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads a with from the classpath with the default provider")
  void classpathKeystoreWithDefaultProvider() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads a with from the classpath with the default provider and type")
  void classpathKeystoreWithDefaultProviderAndType() throws KeyStoreException {
    KeyStore keystore = Bruce.keystore.with("classpath:/keystore.p12", "password".toCharArray());
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads a with from an https url")
  void httpsKeystore() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with(
            "https://github.com/mcaserta/spring-crypto-utils/raw/1.4/src/test/resources/keystore.jks",
            "password".toCharArray(),
            "JKS",
            "SUN");
    assertNotNull(keystore);
    assertEquals("JKS", keystore.getType(), "type");
    assertEquals(1, keystore.size(), "size");
  }

  @Test
  @DisplayName("loading a non existent with should throw an exception")
  void nonExistent() {
    var password = "bar".toCharArray();
    assertThrows(BruceException.class, () -> Bruce.keystore.with("foo", password));
  }

  @Test
  @DisplayName("loading a with with the wrong type should throw an exception")
  void noSuchType() {
    var password = "password".toCharArray();
    assertThrows(
        BruceException.class, () -> Bruce.keystore.with("classpath:with.jks", password, "foo"));
  }

  @Test
  @DisplayName("loading a with with the wrong provider should throw an exception")
  void noSuchProvider() {
    var password = "password".toCharArray();
    assertThrows(
        BruceException.class,
        () -> Bruce.keystore.with("classpath:with.jks", password, "JKS", "foo"));
  }
}
