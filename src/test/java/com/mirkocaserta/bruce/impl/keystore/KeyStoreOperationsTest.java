package com.mirkocaserta.bruce.impl.keystore;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.KeyStore;
import java.security.KeyStoreException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyStoreOperationsTest {

    @Test
    void loadCertificateWrapsKeyStoreException() throws Exception {
        KeyStore keyStore = mock(KeyStore.class);
        when(keyStore.getCertificate(anyString())).thenThrow(new KeyStoreException("boom"));

        assertThrows(BruceException.class, () -> KeyStoreOperations.loadCertificate(keyStore, "missing"));
    }

    @Test
    void loadPrivateKeyWrapsKeyStoreException() throws Exception {
        KeyStore keyStore = mock(KeyStore.class);
        when(keyStore.getEntry(anyString(), any(KeyStore.ProtectionParameter.class))).thenThrow(new KeyStoreException("boom"));

        assertThrows(BruceException.class, () -> KeyStoreOperations.loadPrivateKey(keyStore, "missing", "password".toCharArray()));
    }

    @Test
    void loadSecretKeyWrapsKeyStoreException() throws Exception {
        KeyStore keyStore = mock(KeyStore.class);
        when(keyStore.getKey(anyString(), any(char[].class))).thenThrow(new KeyStoreException("boom"));

        assertThrows(BruceException.class, () -> KeyStoreOperations.loadSecretKey(keyStore, "missing", "password".toCharArray()));
    }
}

