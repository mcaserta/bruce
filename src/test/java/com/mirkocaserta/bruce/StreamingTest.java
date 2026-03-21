package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

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
}

