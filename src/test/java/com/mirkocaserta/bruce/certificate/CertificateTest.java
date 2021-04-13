package com.mirkocaserta.bruce.certificate;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

import static com.mirkocaserta.bruce.Bruce.certificate;
import static com.mirkocaserta.bruce.Bruce.keystore;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class CertificateTest {

    @Test
    @DisplayName("loads a certificate")
    void certificateLoad() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        Certificate certificate = certificate(keystore, "test");
        assertNotNull(certificate);
        assertEquals("X.509", certificate.getType(), "type");
        assertNotNull(certificate.getPublicKey());
        assertEquals("RSA", certificate.getPublicKey().getAlgorithm(), "algorithm");
        assertEquals("X.509", certificate.getPublicKey().getFormat(), "format");
    }

    @Test
    @DisplayName("loading a non existing certificate should throw an error")
    void nonExistingKey() throws KeyStoreException {
        KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
        assertNotNull(keystore);
        assertEquals("PKCS12", keystore.getType(), "type");
        assertEquals(2, keystore.size(), "size");
        assertThrows(BruceException.class, () -> certificate(keystore, "sgiao belo"));
    }

    @Test
    @DisplayName("an exception in getCertificate should be wrapped in a BruceException")
    void getCertificateExceptionGetsWrapped() {
        KeyStore keystore = mock(KeyStore.class);
        assertThrows(BruceException.class, () -> certificate(keystore, "test"));
    }

}
