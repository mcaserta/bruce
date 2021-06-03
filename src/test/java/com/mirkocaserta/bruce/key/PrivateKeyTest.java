package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;

import static com.mirkocaserta.bruce.Bruce.keystore;
import static com.mirkocaserta.bruce.Bruce.privateKey;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class PrivateKeyTest {

    @Test
    @DisplayName("loads a private key")
    void privateKeyTest() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        PrivateKey privateKey = privateKey(keystore, "test", "password".toCharArray());
        assertNotNull(privateKey);
        assertEquals("RSA", privateKey.getAlgorithm(), "algorithm");
        assertEquals("PKCS#8", privateKey.getFormat(), "format");
    }

    @Test
    @DisplayName("loading a non existing private key should throw an error")
    void nonExistingKey() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        assertThrows(BruceException.class, () -> privateKey(keystore, "sgiao belo", "foo".toCharArray()));
    }

    @Test
    @DisplayName("an exception thrown in getPrivateKey should be wrapped")
    void exceptionsShouldBeWrapped() {
        KeyStore keystore = mock(KeyStore.class);
        assertThrows(BruceException.class, () -> privateKey(keystore, "test", "password".toCharArray()));
    }

}
