package com.mirkocaserta.bruce.impl.keystore;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    @Test
    void storeKeyStoreSerializesLoadedKeystore() {
        var keyStore = KeyStoreOperations.loadKeyStore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");

        byte[] data = KeyStoreOperations.storeKeyStore(keyStore, "password".toCharArray());

        assertNotNull(data);
        assertTrue(data.length > 0);
    }

    @Test
    void storeKeyStoreWritesToPath() throws Exception {
        var keyStore = KeyStoreOperations.loadKeyStore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
        Path output = Files.createTempFile("bruce-keystore-ops-", ".p12");

        KeyStoreOperations.storeKeyStore(keyStore, "password".toCharArray(), output);

        assertTrue(Files.size(output) > 0);
        Files.deleteIfExists(output);
    }

    @Test
    void storeKeyStoreRejectsNullInputs() {
        assertThrows(BruceException.class, () -> KeyStoreOperations.storeKeyStore(null, "password".toCharArray()));

        assertThrows(BruceException.class,
                () -> KeyStoreOperations.storeKeyStore(mock(KeyStore.class), null));

        assertThrows(BruceException.class,
                () -> KeyStoreOperations.storeKeyStore(mock(KeyStore.class), "password".toCharArray(), null));
    }

    @Test
    void storeKeyStoreWrapsSerializationFailure() throws Exception {
        KeyStore uninitialized = KeyStore.getInstance("PKCS12");

        assertThrows(BruceException.class,
                () -> KeyStoreOperations.storeKeyStore(uninitialized, "password".toCharArray()));
    }

    @Test
    void storeKeyStoreWrapsWriteFailure() throws Exception {
        var keyStore = KeyStoreOperations.loadKeyStore("classpath:/keystore-alice.p12", "password".toCharArray(), "PKCS12");
        Path tempDir = Files.createTempDirectory("bruce-keystore-ops-dir-");
        Path missingParent = tempDir.resolve("missing-dir").resolve("keystore.p12");

        assertThrows(BruceException.class,
                () -> KeyStoreOperations.storeKeyStore(keyStore, "password".toCharArray(), missingParent));

        Files.deleteIfExists(tempDir);
    }
}

