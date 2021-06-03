package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static com.mirkocaserta.bruce.Bruce.keystore;
import static com.mirkocaserta.bruce.Bruce.privateKey;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class PrivateKeyTest {

    @Test
    @DisplayName("loads a private key")
    void privateKeyTest() throws KeyStoreException {
        var keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        var privateKey = privateKey(keystore, "test", "password".toCharArray());
        assertNotNull(privateKey);
        assertEquals("RSA", privateKey.getAlgorithm(), "algorithm");
        assertEquals("PKCS#8", privateKey.getFormat(), "format");
    }

    @Test
    @DisplayName("loading a non existing private key should throw an error")
    void nonExistingKey() throws KeyStoreException {
        var keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        var password = "foo".toCharArray();
        assertThrows(BruceException.class, () -> privateKey(keystore, "sgiao belo", password));
    }

    @Test
    @DisplayName("an exception thrown in getPrivateKey should be wrapped")
    void exceptionsShouldBeWrapped() {
        var keystore = mock(KeyStore.class);
        var password = "password".toCharArray();
        assertThrows(BruceException.class, () -> privateKey(keystore, "test", password));
    }

}
