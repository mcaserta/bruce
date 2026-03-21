package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.util.PemUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PEM encoding and decoding operations.
 * Verifies support for encoding/decoding keys and certificates in PEM format.
 */
class PemEncodingTest {

    @Test
    void pemEncodeDecodeRoundTrip() {
        byte[] original = "test content".getBytes();
        String pem = PemUtils.encode(PemType.CERTIFICATE, original);
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(pem.endsWith("-----END CERTIFICATE-----"));
        assertArrayEquals(original, PemUtils.decode(pem));
    }

    @Test
    void keystoresPrivateKeyFromPemRoundTrip() {
        KeyPair kp = keyPair("RSA", 2048);
        String pem = keyToPem(kp.getPrivate());
        assertTrue(pem.contains("PRIVATE KEY"));

        var restored = privateKeyFromPem(pem, "RSA");
        assertArrayEquals(kp.getPrivate().getEncoded(), restored.getEncoded());
    }

    @Test
    void keystoresPublicKeyFromPemRoundTrip() {
        KeyPair kp = keyPair("RSA", 2048);
        String pem = keyToPem(kp.getPublic());
        assertTrue(pem.contains("PUBLIC KEY"));

        var restored = publicKeyFromPem(pem, "RSA");
        assertArrayEquals(kp.getPublic().getEncoded(), restored.getEncoded());
    }

    @Test
    void keystoresCertificateFromPemRoundTrip() {
        var ks = keystore("classpath:/keystore.p12", "password".toCharArray(), Keystores.DEFAULT_KEYSTORE_TYPE);
        var cert = certificate(ks, "test");
        String pem = certificateToPem(cert);
        assertTrue(pem.contains("CERTIFICATE"));

        var restored = certificateFromPem(pem);
        assertEquals(cert, restored);
    }

    @Test
    void bytesToPemAndFromPem() {
        KeyPair kp = keyPair("RSA", 2048);
        byte[] encoded = kp.getPublic().getEncoded();
        Bytes original = Bytes.from(encoded);

        String pem = original.toPem(PemType.PUBLIC_KEY);
        Bytes restored = Bytes.fromPem(pem);

        assertEquals(original, restored);
    }

    @Test
    void pemDecodeRejectsInvalidInput() {
        assertThrows(BruceException.class, () -> PemUtils.decode(null));
        assertThrows(BruceException.class, () -> PemUtils.decode("  "));
    }
}

