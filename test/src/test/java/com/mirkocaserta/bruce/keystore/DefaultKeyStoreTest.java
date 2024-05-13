package com.mirkocaserta.bruce.keystore;

import static com.mirkocaserta.bruce.api.KeyStoreParam.type;
import static com.mirkocaserta.bruce.api.KeyStoreParam.useSystemProperties;
import static org.junit.jupiter.api.Assertions.*;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStoreException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DefaultKeyStoreTest {

  @Test
  @DisplayName("loads the keystore from the default system properties")
  void defaultKeystore() throws KeyStoreException {
    System.setProperty("javax.net.ssl.keyStore", "src/test/resources/keystore.p12");
    System.setProperty("javax.net.ssl.keyStorePassword", "password");
    final var keystore = Bruce.keystore.with(useSystemProperties());
    assertNotNull(keystore);
    assertEquals("PKCS12", keystore.getType(), "type");
    assertEquals(2, keystore.size(), "size");
  }

  @Test
  @DisplayName("loads the keystore from the default system properties with a specific with type")
  void defaultKeystoreWithType() throws KeyStoreException {
    System.setProperty("javax.net.ssl.keyStore", "src/test/resources/keystore.jks");
    System.setProperty("javax.net.ssl.keyStorePassword", "password");
    final var keystore = Bruce.keystore.with(useSystemProperties(), type("JKS"));
    assertNotNull(keystore);
    assertEquals("JKS", keystore.getType(), "type");
    assertEquals(1, keystore.size(), "size");
  }

  @ParameterizedTest
  @ValueSource(strings = {"sgiao belo", "   ", ""})
  @DisplayName("these keystore locations should throw an error")
  void badLocations(String location) {
    System.setProperty("javax.net.ssl.keyStore", location);
    System.setProperty("javax.net.ssl.keyStorePassword", "wrong");
    assertThrows(BruceException.class, () -> Bruce.keystore.with(useSystemProperties()));
  }

  @AfterEach
  void cleanup() {
    // we need to clean up these properties as otherwise tests that rely
    // on https aren't going to work
    System.setProperty("javax.net.ssl.keyStore", "");
    System.setProperty("javax.net.ssl.keyStorePassword", "");
  }
}
