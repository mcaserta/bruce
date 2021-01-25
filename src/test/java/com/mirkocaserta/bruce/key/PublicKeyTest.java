package com.mirkocaserta.bruce.key;

import com.mirkocaserta.bruce.CryptException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;

import static com.mirkocaserta.bruce.Crypt.keystore;
import static com.mirkocaserta.bruce.Crypt.publicKey;
import static org.junit.jupiter.api.Assertions.*;

class PublicKeyTest {

    @Test
    @DisplayName("loads a public key")
    void publicKeyTest() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        PublicKey publicKey = publicKey(keystore, "test");
        assertNotNull(publicKey);
        assertEquals("RSA", publicKey.getAlgorithm(), "algorithm");
        assertEquals("X.509", publicKey.getFormat(), "format");
    }

    @Test
    @DisplayName("loading a non existing public key should throw an error")
    void nonExistingKey() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        assertThrows(CryptException.class, () -> publicKey(keystore, "sgiao belo"));
    }

}
