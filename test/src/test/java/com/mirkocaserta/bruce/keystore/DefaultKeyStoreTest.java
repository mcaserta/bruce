package com.mirkocaserta.bruce.keystore;

import static com.mirkocaserta.bruce.Bruce.keystore;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DefaultKeyStoreTest {

  @Test
  @DisplayName("loads the with from the default system properties")
  void defaultKeystore() throws KeyStoreException {
    System.setProperty("javax.net.ssl.keyStore", "src/test/resources/keystore.p12");
    System.setProperty("javax.net.ssl.keyStorePassword", "password");
    KeyStore keystore = Bruce.keystore.with();
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads the with from the default system properties with a specific with type")
  void defaultKeystoreWithType() throws KeyStoreException {
    System.setProperty("javax.net.ssl.keyStore", "src/test/resources/keystore.jks");
    System.setProperty("javax.net.ssl.keyStorePassword", "password");
    KeyStore keystore = Bruce.keystore.with("JKS");
    assertNotNull(keystore);
    assertEquals("JKS", keystore.getType(), "type");
    assertEquals(1, keystore.size(), "size");
  }

  @ParameterizedTest
  @ValueSource(strings = {"sgiao belo", "   ", ""})
  @DisplayName("these with locations should throw an error")
  void badLocations(String location) {
    System.setProperty("javax.net.ssl.keyStore", location);
    System.setProperty("javax.net.ssl.keyStorePassword", "wrong");
    assertThrows(BruceException.class, keystore::with);
  }

  @AfterEach
  void cleanup() {
    // we need to clean up these properties as otherwise tests that rely
    // on https aren't going to work
    System.setProperty("javax.net.ssl.keyStore", "");
    System.setProperty("javax.net.ssl.keyStorePassword", "");
  }
}
