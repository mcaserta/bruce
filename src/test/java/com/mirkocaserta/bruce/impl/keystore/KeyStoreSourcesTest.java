package com.mirkocaserta.bruce.impl.keystore;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyStoreSourcesTest {

    @Test
    void classpathSourceSupportsAndOpens() throws IOException {
        ClasspathKeyStoreSource source = new ClasspathKeyStoreSource();
        assertTrue(source.supports("classpath:/keystore.p12"));
        assertFalse(source.supports("file:src/test/resources/keystore.p12"));

        try (var stream = source.open("classpath:/keystore.p12")) {
            assertNotNull(stream);
            assertTrue(stream.read() >= 0);
        }
    }

    @Test
    void fileSourceSupportsAndOpens() throws IOException {
        FileKeyStoreSource source = new FileKeyStoreSource();
        assertFalse(source.supports(null));
        assertTrue(source.supports("src/test/resources/keystore.p12"));

        try (var stream = source.open("src/test/resources/keystore.p12")) {
            assertNotNull(stream);
            assertTrue(stream.read() >= 0);
        }
    }

    @Test
    void httpAndHttpsSourcesSupportExpectedSchemes() {
        HttpKeyStoreSource http = new HttpKeyStoreSource();
        HttpsKeyStoreSource https = new HttpsKeyStoreSource();

        assertTrue(http.supports("http://localhost:8080/keystore.p12"));
        assertFalse(http.supports("https://localhost:8443/keystore.p12"));

        assertTrue(https.supports("https://localhost:8443/keystore.p12"));
        assertFalse(https.supports("http://localhost:8080/keystore.p12"));
    }

    @Test
    void resolverOpensClasspathAndFileLocations() throws IOException {
        try (var classpathStream = KeyStoreSources.open("classpath:/keystore.p12")) {
            assertNotNull(classpathStream);
            assertTrue(classpathStream.read() >= 0);
        }

        try (var fileStream = KeyStoreSources.open("src/test/resources/keystore.p12")) {
            assertNotNull(fileStream);
            assertTrue(fileStream.read() >= 0);
        }
    }

    @Test
    void classpathOpenFailsForMissingResource() {
        assertThrows(IOException.class, () -> {
            try (var ignored = KeyStoreSources.open("classpath:/missing-keystore.p12")) {
                // no-op
            }
        });
    }

    @Test
    void resolverFailsForUnsupportedLocation() {
        assertThrows(IOException.class, () -> {
            try (var ignored = KeyStoreSources.open("ftp://example.com/keystore.p12")) {
                // no-op
            }
        });
    }
}

