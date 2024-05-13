package com.mirkocaserta.bruce.keystore;

import static com.mirkocaserta.bruce.api.KeyStoreParam.*;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KeyStoreTest {

  @DisplayName("loads a with from the classpath and the filesystem")
  @ParameterizedTest
  @ValueSource(
      strings = {
        "classpath:/keystore.p12",
        "file:src/test/resources/keystore.p12",
        "src/test/resources/keystore.p12"
      })
  void classpathKeystore(String location) throws KeyStoreException {
    KeyStore keystore = Bruce.keystore.with(location(location), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads a with from the classpath with the default provider")
  void classpathKeystoreWithDefaultProvider() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"),
            password("password".toCharArray()),
            type("PKCS12"));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads a with from the classpath with the default provider and type")
  void classpathKeystoreWithDefaultProviderAndType() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with(
            location("classpath:/keystore.p12"), password("password".toCharArray()));
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads a with from an https url")
  void httpsKeystore() throws KeyStoreException {
    KeyStore keystore =
        Bruce.keystore.with(
            location(
                "https://github.com/mcaserta/spring-crypto-utils/raw/1.4/src/test/resources/keystore.jks"),
            password("password".toCharArray()),
            type("JKS"),
            provider("SUN"));
    assertNotNull(keystore);
    assertEquals("JKS", keystore.getType(), "type");
    assertEquals(1, keystore.size(), "size");
  }

  @Test
  @DisplayName("loading a non existent with should throw an exception")
  void nonExistent() {
    var password = "bar".toCharArray();
    assertThrows(
        BruceException.class, () -> Bruce.keystore.with(location("foo"), password(password)));
  }

  @Test
  @DisplayName("loading a with with the wrong type should throw an exception")
  void noSuchType() {
    var password = "password".toCharArray();
    assertThrows(
        BruceException.class,
        () -> Bruce.keystore.with(location("classpath:with.jks"), password(password), type("foo")));
  }

  @Test
  @DisplayName("loading a with with the wrong provider should throw an exception")
  void noSuchProvider() {
    var password = "password".toCharArray();
    assertThrows(
        BruceException.class,
        () ->
            Bruce.keystore.with(
                location("classpath:with.jks"), password(password), type("JKS"), provider("foo")));
  }
}
