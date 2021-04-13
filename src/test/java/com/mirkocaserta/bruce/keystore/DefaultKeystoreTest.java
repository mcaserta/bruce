package com.mirkocaserta.bruce.keystore;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static com.mirkocaserta.bruce.Bruce.DEFAULT_KEYSTORE_TYPE;
import static com.mirkocaserta.bruce.Bruce.keystore;
import static org.junit.jupiter.api.Assertions.*;

class DefaultKeystoreTest {

    @Test
    @DisplayName("loads the keystore from the default system properties")
    void defaultKeystore() throws KeyStoreException {
        System.setProperty("javax.net.ssl.keyStore", "src/test/resources/keystore.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        KeyStore keystore = keystore();
        assertNotNull(keystore);
        assertEquals(DEFAULT_KEYSTORE_TYPE, keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
    }

    @Test
    @DisplayName("loads the keystore from the default system properties with a specific keystore type")
    void defaultKeystoreWithType() throws KeyStoreException {
        System.setProperty("javax.net.ssl.keyStore", "src/test/resources/keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        KeyStore keystore = keystore("JKS");
        assertNotNull(keystore);
        assertEquals("JKS", keystore.getType(), "type");
        assertEquals(1, keystore.size(), "size");
    }

    @Test
    @DisplayName("loading a non existing keystore should throw an error")
    void nonExisting() {
        System.setProperty("javax.net.ssl.keyStore", "sgiao belo");
        System.setProperty("javax.net.ssl.keyStorePassword", "wrong");
        assertThrows(BruceException.class, Bruce::keystore);
    }

    @Test
    @DisplayName("loading a blank location should throw an error")
    void blankLocation() {
        System.setProperty("javax.net.ssl.keyStore", "   ");
        System.setProperty("javax.net.ssl.keyStorePassword", "wrong");
        assertThrows(BruceException.class, Bruce::keystore);
    }

    @Test
    @DisplayName("loading an empty location should throw an error")
    void emptyLocation() {
        System.setProperty("javax.net.ssl.keyStore", "");
        System.setProperty("javax.net.ssl.keyStorePassword", "wrong");
        assertThrows(BruceException.class, Bruce::keystore);
    }

    @AfterEach
    void cleanup() {
        // we need to clean up these properties as otherwise tests that rely
        // on https aren't going to work
        System.setProperty("javax.net.ssl.keyStore", "");
        System.setProperty("javax.net.ssl.keyStorePassword", "");
    }

}
