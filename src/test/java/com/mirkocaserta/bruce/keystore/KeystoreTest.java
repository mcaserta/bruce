package com.mirkocaserta.bruce.keystore;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static com.mirkocaserta.bruce.Bruce.DEFAULT_KEYSTORE_TYPE;
import static com.mirkocaserta.bruce.Bruce.keystore;
import static org.junit.jupiter.api.Assertions.*;

class KeystoreTest {

    @DisplayName("loads a keystore from the classpath and the filesystem")
    @ParameterizedTest
    @ValueSource(strings = {"classpath:/keystore.p12", "file:src/test/resources/keystore.p12", "src/test/resources/keystore.p12"})
    void classpathKeystore(String location) throws KeyStoreException {
        KeyStore keystore = keystore(location, "password".toCharArray());
        assertNotNull(keystore);
        assertEquals(DEFAULT_KEYSTORE_TYPE, keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
    }

    @Test
    @DisplayName("loads a keystore from the classpath with the default provider")
    void classpathKeystoreWithDefaultProvider() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), DEFAULT_KEYSTORE_TYPE);
        assertNotNull(keystore);
        assertEquals(DEFAULT_KEYSTORE_TYPE, keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
    }

    @Test
    @DisplayName("loads a keystore from the classpath with the default provider and type")
    void classpathKeystoreWithDefaultProviderAndType() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray());
        assertNotNull(keystore);
        assertEquals(DEFAULT_KEYSTORE_TYPE, keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
    }

    @Test
    @DisplayName("loads a keystore from an https url")
    void httpsKeystore() throws KeyStoreException {
        KeyStore keystore = keystore("https://github.com/mcaserta/spring-crypto-utils/raw/1.4/src/test/resources/keystore.jks", "password".toCharArray(), "JKS", "SUN");
        assertNotNull(keystore);
        assertEquals("JKS", keystore.getType(), "type");
        assertEquals(1, keystore.size(), "size");
    }

    @Test
    @DisplayName("loading a non existent keystore should throw an exception")
    void nonExistent() {
        var password = "bar".toCharArray();
        assertThrows(BruceException.class, () -> keystore("foo", password));
    }

    @Test
    @DisplayName("loading a keystore with the wrong type should throw an exception")
    void noSuchType() {
        var password = "password".toCharArray();
        assertThrows(BruceException.class, () -> keystore("classpath:keystore.jks", password, "foo"));
    }

    @Test
    @DisplayName("loading a keystore with the wrong provider should throw an exception")
    void noSuchProvider() {
        var password = "password".toCharArray();
        assertThrows(BruceException.class, () -> keystore("classpath:keystore.jks", password, "JKS", "foo"));
    }

}
