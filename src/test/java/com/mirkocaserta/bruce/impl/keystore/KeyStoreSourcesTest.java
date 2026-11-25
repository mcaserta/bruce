package com.mirkocaserta.bruce.impl.keystore;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
        assertTrue(source.supports("file:src/test/resources/keystore.p12"));
        assertTrue(source.supports("file:///tmp/keystore.p12"));
        assertTrue(source.supports("C:\\keys\\keystore.p12"));
        assertTrue(source.supports("C:/keys/keystore.p12"));

        try (var stream = source.open("src/test/resources/keystore.p12")) {
            assertNotNull(stream);
            assertTrue(stream.read() >= 0);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ftp://example.com/keystore.p12",
            "htps://example.com/keystore.p12",
            "http://example.com/keystore.p12",
            "s3://bucket/keystore.p12"
    })
    void fileSourceDoesNotClaimUrlSchemes(String location) {
        assertFalse(new FileKeyStoreSource().supports(location));
    }

    @Test
    void httpsSourceSupportsOnlyHttps() {
        HttpsKeyStoreSource https = new HttpsKeyStoreSource();

        assertTrue(https.supports("https://localhost:8443/keystore.p12"));
        assertTrue(https.supports("HTTPS://localhost:8443/keystore.p12"));
        assertFalse(https.supports("http://localhost:8080/keystore.p12"));
        assertFalse(https.supports(null));
    }

    @Test
    void httpsSourceConfiguresTimeouts() throws IOException {
        URLConnection connection = new HttpsKeyStoreSource().connect("https://localhost:1/keystore.p12");

        assertEquals(10_000, connection.getConnectTimeout());
        assertEquals(30_000, connection.getReadTimeout());
        assertEquals(HttpsKeyStoreSource.CONNECT_TIMEOUT_MILLIS, connection.getConnectTimeout());
        assertEquals(HttpsKeyStoreSource.READ_TIMEOUT_MILLIS, connection.getReadTimeout());
        assertTrue(connection instanceof HttpsURLConnection);
        assertTrue(((HttpURLConnection) connection).getInstanceFollowRedirects());
    }

    @Test
    void httpsSourceRejectsNonHttpsConnection() throws IOException {
        URLConnection plain = URI.create("http://localhost:1/keystore.p12").toURL().openConnection();
        HttpsKeyStoreSource source = new HttpsKeyStoreSource(url -> plain);

        IOException e = assertThrows(IOException.class, () -> source.open("https://localhost:1/keystore.p12"));
        assertTrue(e.getMessage().contains("https"), e.getMessage());
    }

    @Test
    void httpsSourceReturnsConnectionStream() throws IOException {
        HttpsURLConnection connection = mock(HttpsURLConnection.class);
        var stream = new ByteArrayInputStream(new byte[]{1});
        when(connection.getInputStream()).thenReturn(stream);
        HttpsKeyStoreSource source = new HttpsKeyStoreSource(url -> connection);

        assertSame(stream, source.open("https://localhost:1/keystore.p12"));
    }

    @Test
    void httpsSourceRedactsUserInfoFromConnectionErrors() throws IOException {
        HttpsURLConnection connection = mock(HttpsURLConnection.class);
        when(connection.getInputStream())
                .thenThrow(new FileNotFoundException("https://user:secret@example.com/ks.p12"));
        HttpsKeyStoreSource source = new HttpsKeyStoreSource(url -> connection);

        IOException e = assertThrows(IOException.class, () -> source.open("https://user:secret@example.com/ks.p12"));
        assertNoSecretInChain(e);
        assertTrue(e.getMessage().contains("***@example.com"), e.getMessage());
    }

    @Test
    void httpsSourceRethrowsErrorsWithoutUserInfoUnchanged() throws IOException {
        HttpsURLConnection connection = mock(HttpsURLConnection.class);
        FileNotFoundException original = new FileNotFoundException("https://example.com/ks.p12");
        when(connection.getInputStream()).thenThrow(original);
        HttpsKeyStoreSource source = new HttpsKeyStoreSource(url -> connection);

        assertSame(original, assertThrows(IOException.class, () -> source.open("https://example.com/ks.p12")));
    }

    @Test
    void httpsSourceRedactsUserInfoFromMalformedLocation() {
        IOException e = assertThrows(IOException.class,
                () -> new HttpsKeyStoreSource().open("https://user:secret@exa mple.com/ks.p12"));
        assertNoSecretInChain(e);
        assertTrue(e.getMessage().contains("https://***@exa mple.com/ks.p12"), e.getMessage());
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

        try (var filePrefixStream = KeyStoreSources.open("file:src/test/resources/keystore.p12")) {
            assertTrue(filePrefixStream.read() >= 0);
        }
    }

    @Test
    void resolverOpensFileUri() throws IOException {
        Path keystore = Path.of("src/test/resources/keystore.p12").toAbsolutePath();
        // on Windows the absolute path starts with a drive letter, which file:// cannot express as-is
        org.junit.jupiter.api.Assumptions.assumeTrue(keystore.toString().startsWith("/"));
        try (var fileUriStream = KeyStoreSources.open("file://" + keystore)) {
            assertTrue(fileUriStream.read() >= 0);
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

    @ParameterizedTest
    @ValueSource(strings = {"ftp://example.com/keystore.p12", "htps://example.com/keystore.p12"})
    void resolverFailsForUnsupportedScheme(String location) {
        IOException e = assertThrows(IOException.class, () -> KeyStoreSources.open(location));
        assertTrue(e.getMessage().startsWith("unsupported keystore location scheme"), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/keystore.p12", "HTTP://example.com/keystore.p12"})
    void resolverRejectsPlainHttp(String location) {
        IOException e = assertThrows(IOException.class, () -> KeyStoreSources.open(location));
        assertTrue(e.getMessage().contains("plain HTTP is not supported"), e.getMessage());
        assertTrue(e.getMessage().contains("https://"), e.getMessage());
    }

    @Test
    void resolverRedactsUserInfoInErrors() {
        IOException http = assertThrows(IOException.class,
                () -> KeyStoreSources.open("http://user:secret@example.com/ks.p12"));
        assertNoSecretInChain(http);
        assertTrue(http.getMessage().contains("***@example.com"), http.getMessage());

        IOException ftp = assertThrows(IOException.class,
                () -> KeyStoreSources.open("ftp://user:secret@example.com/ks.p12"));
        assertNoSecretInChain(ftp);
        assertTrue(ftp.getMessage().contains("***@example.com"), ftp.getMessage());
    }

    @Test
    void schemeDetection() {
        assertEquals("https", KeyStoreSources.scheme("https://example.com/ks.p12"));
        assertEquals("http", KeyStoreSources.scheme("HTTP://example.com/ks.p12"));
        assertEquals("file", KeyStoreSources.scheme("file:///tmp/ks.p12"));
        assertNull(KeyStoreSources.scheme("C:\\keys\\ks.p12"));
        assertNull(KeyStoreSources.scheme("C:/keys/ks.p12"));
        assertNull(KeyStoreSources.scheme("classpath:/ks.p12"));
        assertNull(KeyStoreSources.scheme("file:ks.p12"));
        assertNull(KeyStoreSources.scheme("keys/ks.p12"));
        assertNull(KeyStoreSources.scheme("1abc://x"));
        assertNull(KeyStoreSources.scheme(null));
    }

    @Test
    void redaction() {
        assertEquals("https://***@example.com/ks.p12", KeyStoreSources.redact("https://user:pass@example.com/ks.p12"));
        assertEquals("https://***@example.com/ks.p12", KeyStoreSources.redact("https://user:p@ss@example.com/ks.p12"));
        assertEquals("https://***@example.com/ks.p12", KeyStoreSources.redact("https://token@example.com/ks.p12"));
        assertEquals("https://example.com/a@b.p12", KeyStoreSources.redact("https://example.com/a@b.p12"));
        assertEquals("https://example.com/ks.p12?***", KeyStoreSources.redact("https://example.com/ks.p12?u=a@b"));
        assertEquals("https://bucket.s3.amazonaws.com/ks.p12?*** failed",
                KeyStoreSources.redact("https://bucket.s3.amazonaws.com/ks.p12?X-Amz-Signature=abc123&X-Amz-Expires=60 failed"));
        assertEquals("https://example.com/ks.p12#***", KeyStoreSources.redact("https://example.com/ks.p12#token=abc"));
        assertEquals("https://***@example.com/ks.p12?***", KeyStoreSources.redact("https://u:p@example.com/ks.p12?t=1"));
        assertEquals("keys/ks.p12", KeyStoreSources.redact("keys/ks.p12"));
        assertNull(KeyStoreSources.redact(null));
    }

    @Test
    void loadKeyStoreDoesNotLeakUserInfo() {
        BruceException e = assertThrows(BruceException.class,
                () -> KeyStoreOperations.loadKeyStore("https://user:secret@exa mple.com/ks.p12", "pw".toCharArray()));
        assertNoSecretInChain(e);
        assertTrue(e.getMessage().contains("https://***@exa mple.com/ks.p12"), e.getMessage());

        BruceException http = assertThrows(BruceException.class,
                () -> KeyStoreOperations.loadKeyStore("http://user:secret@example.com/ks.p12", "pw".toCharArray()));
        assertNoSecretInChain(http);
        assertTrue(http.getMessage().contains("plain HTTP is not supported"), http.getMessage());

        BruceException file = assertThrows(BruceException.class,
                () -> KeyStoreOperations.loadKeyStore("file://user:secret@host/ks.p12", "pw".toCharArray()));
        assertNoSecretInChain(file);
    }

    @Test
    void sanitizeLeavesExceptionsWithoutUserInfoAlone() {
        IOException original = new IOException("boom");
        assertSame(original, KeyStoreSources.sanitize(original, "https://example.com/ks.p12"));
        assertSame(original, KeyStoreSources.sanitize(original, "https://user:secret@example.com/ks.p12"));
        assertSame(original, KeyStoreSources.sanitize(original, "https://@example.com/ks.p12"));

        IOException nested = new IOException("outer", new IOException("//user:secret@host/ks.p12"));
        IOException sanitized = KeyStoreSources.sanitize(nested, "file://user:secret@host/ks.p12");
        assertNoSecretInChain(sanitized);
        assertTrue(sanitized.getMessage().contains("***@host"), sanitized.getMessage());
    }

    @Test
    void sanitizeRedactsQueryTokens() {
        IOException leaky = new IOException("Server returned 403 for https://example.com/ks.p12?token=secret");
        IOException sanitized = KeyStoreSources.sanitize(leaky, "https://example.com/ks.p12?token=secret");
        assertNoSecretInChain(sanitized);
    }

    @Test
    void loadKeyStoreDoesNotLeakQueryTokens() {
        BruceException e = assertThrows(BruceException.class,
                () -> KeyStoreOperations.loadKeyStore("https://exa%zzmple.com/ks.p12?token=secret", "pw".toCharArray()));
        assertNoSecretInChain(e);
    }

    @Test
    void invalidFilePathDoesNotLeakTheLocation() {
        BruceException e = assertThrows(BruceException.class,
                () -> KeyStoreOperations.loadKeyStore("file://user:secret@host/ks\u0000.p12", "pw".toCharArray()));
        assertNoSecretInChain(e);
    }

    @Test
    void boundedStreamStopsAtTheSizeLimit() throws IOException {
        var in = new BoundedInputStream(new java.io.ByteArrayInputStream(new byte[100]), 64, java.time.Duration.ofMinutes(1));
        IOException e = assertThrows(IOException.class, () -> in.readAllBytes());
        assertTrue(e.getMessage().contains("64"), e.getMessage());
    }

    @Test
    void boundedStreamPassesSmallInputThrough() throws IOException {
        var data = new byte[]{1, 2, 3, 4};
        try (var in = new BoundedInputStream(new java.io.ByteArrayInputStream(data), 4, java.time.Duration.ofMinutes(1))) {
            assertEquals(1, in.read());
            org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[]{2, 3, 4}, in.readAllBytes());
            assertEquals(-1, in.read());
        }
    }

    @Test
    void boundedStreamCountsSkippedBytes() throws IOException {
        var in = new BoundedInputStream(new java.io.ByteArrayInputStream(new byte[100]), 64, java.time.Duration.ofMinutes(1));
        assertFalse(in.markSupported());
        assertEquals(60, in.skip(60));
        assertThrows(IOException.class, () -> in.skip(10));
    }

    @Test
    void boundedStreamEnforcesTheDeadline() {
        var slow = new java.io.InputStream() {
            @Override public int read() {
                try { Thread.sleep(20); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                return 0;
            }
        };
        var in = new BoundedInputStream(slow, Long.MAX_VALUE, java.time.Duration.ofMillis(50));
        IOException e = assertThrows(IOException.class, () -> { for (int i = 0; i < 100; i++) in.read(); });
        assertTrue(e.getMessage().contains("time"), e.getMessage());
    }

    private static void assertNoSecretInChain(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            assertFalse(c.toString().contains("secret"), "secret leaked in " + c);
        }
    }
}
