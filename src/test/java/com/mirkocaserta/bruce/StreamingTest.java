package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for streaming variants of signers, verifiers, and MAC operations.
 * Verifies that APIs support InputStream input in addition to byte arrays and Bytes.
 */
class StreamingTest {

    @Test
    void signerAndVerifierSupportInputStream() {
        var keyPair = keyPair("RSA", 2048);
        var signer   = Bruce.signerBuilder().key(keyPair.getPrivate()).algorithm("SHA256withRSA").build();
        var verifier = Bruce.verifierBuilder().key(keyPair.getPublic()).algorithm("SHA256withRSA").build();

        byte[] messageBytes = "Hello streaming world".getBytes(StandardCharsets.UTF_8);

        Bytes signature = signer.sign(Bytes.from(new ByteArrayInputStream(messageBytes)));
        assertNotNull(signature);
        assertFalse(signature.isEmpty());

        assertTrue(verifier.verify(Bytes.from(new ByteArrayInputStream(messageBytes)), signature));
        // Different content must fail
        assertFalse(verifier.verify(Bytes.from(new ByteArrayInputStream("tampered".getBytes())), signature));
    }

    @Test
    void macSupportsInputStream() {
        var ks = keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var key = secretKey(ks, "hmac", "password".toCharArray());
        var mac = Bruce.macBuilder().key(key).algorithm("HmacSHA1").build();

        byte[] data = "streaming mac payload".getBytes(StandardCharsets.UTF_8);

        Bytes fromBytes  = mac.get(Bytes.from(data));
        Bytes fromStream = mac.get(Bytes.from(new ByteArrayInputStream(data)));
        assertEquals(fromBytes, fromStream);
    }

    @Test
    void bytesFromStreamReadsAllBytes() {
        byte[] data = {1, 2, 3, 4, 5};
        Bytes result = Bytes.from(new ByteArrayInputStream(data));
        assertArrayEquals(data, result.asBytes());
    }

    @Test
    void digesterPathAndFileProduceSameHash(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("payload.bin");
        Files.write(file, "digest me".getBytes(StandardCharsets.UTF_8));

        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();

        Bytes fromPath = digester.digest(file);
        Bytes fromFile = digester.digest(file.toFile());

        assertEquals(fromPath, fromFile);
    }

    @Test
    void largeFileDigestMatchesJdkStreamingDigest(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("large.bin");
        byte[] payload = new byte[(1024 * 1024) + 123];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) ((i * 31) & 0xFF);
        }
        Files.write(file, payload);

        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();
        Bytes actual = digester.digest(file);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        try (var inputStream = Files.newInputStream(file)) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = inputStream.read(buffer)) > 0) {
                messageDigest.update(buffer, 0, read);
            }
        }

        Bytes expected = Bytes.from(messageDigest.digest());
        assertEquals(expected, actual);
    }

    @Test
    void missingFileIsWrappedInBruceException(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("missing.bin");
        var digester = Bruce.digestBuilder().algorithm("SHA-256").build();

        BruceException exception = assertThrows(BruceException.class, () -> digester.digest(missing));

        assertTrue(exception.getMessage().contains("I/O error reading file"));
        assertNotNull(exception.getCause());
        assertInstanceOf(IOException.class, exception.getCause());
    }
}

