package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;

import static com.mirkocaserta.bruce.Bruce.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class SecretKeyTest {

    @Test
    @DisplayName("loads a secret key")
    void secretKeyTest() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        Key key = secretKey(keystore, "hmac", "password".toCharArray());
        assertNotNull(key);
        assertTrue("HmacSHA256".equals(key.getAlgorithm()) || "1.2.840.113549.2.9".equals(key.getAlgorithm()), "algorithm");
        assertEquals("RAW", key.getFormat(), "format");
    }

    @Test
    @DisplayName("loading a non existing secret key should throw an error")
    void nonExistingKey() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        assertThrows(BruceException.class, () -> secretKey(keystore, "sgiao belo", "foo".toCharArray()));
    }

    @Test
    @DisplayName("an exception should be wrapped")
    void exceptionsShouldBeWrapped() {
        KeyStore keystore = mock(KeyStore.class);
        assertThrows(BruceException.class, () -> secretKey(keystore, "hmac", "password".toCharArray()));
    }

}
