package com.mirkocaserta.bruce;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import static com.mirkocaserta.bruce.Keystores.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for certificate and key format conversions (issue #36):
 * DER format, PKCS#1 RSA format, and PEM ↔ DER utilities.
 */
@DisplayName("Certificate format conversions (issue #36)")
class CertificateConversionTest {

    // ── DER round-trips ───────────────────────────────────────────────────────

    @Nested
    @DisplayName("DER format")
    class DerFormat {

        @Test
        @DisplayName("RSA private key: PKCS#8 DER round-trip")
        void rsaPrivateKeyDerRoundTrip() {
            KeyPair kp = keyPair("RSA", 2048);
            byte[] der = keyToDer(kp.getPrivate());
            assertNotNull(der);
            assertTrue(der.length > 0);

            PrivateKey restored = privateKeyFromDer(der, "RSA");
            assertArrayEquals(kp.getPrivate().getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("RSA public key: SubjectPublicKeyInfo DER round-trip")
        void rsaPublicKeyDerRoundTrip() {
            KeyPair kp = keyPair("RSA", 2048);
            byte[] der = keyToDer(kp.getPublic());
            assertNotNull(der);
            assertTrue(der.length > 0);

            PublicKey restored = publicKeyFromDer(der, "RSA");
            assertArrayEquals(kp.getPublic().getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("X.509 certificate: DER round-trip")
        void certificateDerRoundTrip() {
            var ks = keystore("classpath:/keystore.p12", "password".toCharArray(), DEFAULT_KEYSTORE_TYPE);
            Certificate cert = certificate(ks, "test");

            byte[] der = certificateToDer(cert);
            assertNotNull(der);
            assertTrue(der.length > 0);

            Certificate restored = certificateFromDer(der);
            assertEquals(cert, restored);
        }

        @Test
        @DisplayName("EC private key: PKCS#8 DER round-trip")
        void ecPrivateKeyDerRoundTrip() {
            KeyPair kp = keyPair("EC", 256);
            byte[] der = keyToDer(kp.getPrivate());

            PrivateKey restored = privateKeyFromDer(der, "EC");
            assertArrayEquals(kp.getPrivate().getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("EC public key: SubjectPublicKeyInfo DER round-trip")
        void ecPublicKeyDerRoundTrip() {
            KeyPair kp = keyPair("EC", 256);
            byte[] der = keyToDer(kp.getPublic());

            PublicKey restored = publicKeyFromDer(der, "EC");
            assertArrayEquals(kp.getPublic().getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("keyToDer throws on key with no encoded form")
        void keyToDerThrowsOnNullEncoding() {
            // Use a key implementation that returns null from getEncoded()
            assertThrows(BruceException.class, () -> keyToDer(new NoEncodingKey()));
        }

        @Test
        @DisplayName("privateKeyFromDer throws on unknown algorithm")
        void privateKeyFromDerThrowsOnUnknownAlgorithm() {
            assertThrows(BruceException.class, () -> privateKeyFromDer(new byte[]{0x00}, "INVALID_ALGO"));
        }

        @Test
        @DisplayName("publicKeyFromDer throws on unknown algorithm")
        void publicKeyFromDerThrowsOnUnknownAlgorithm() {
            assertThrows(BruceException.class, () -> publicKeyFromDer(new byte[]{0x00}, "INVALID_ALGO"));
        }

        @Test
        @DisplayName("certificateFromDer throws on invalid bytes")
        void certificateFromDerThrowsOnInvalidBytes() {
            assertThrows(BruceException.class, () -> certificateFromDer(new byte[]{0x00}));
        }

        @Test
        @DisplayName("certificateToDer throws when certificate encoding fails")
        void certificateToDerThrowsOnEncodingFailure() {
            assertThrows(BruceException.class, () -> certificateToDer(new FailingCertificate()));
        }
    }

    // ── PEM ↔ DER ─────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("PEM ↔ DER conversions")
    class PemDerConversions {

        @Test
        @DisplayName("pemToDer / derToPem round-trip")
        void pemToDerAndBack() {
            KeyPair kp = keyPair("RSA", 2048);
            String originalPem = keyToPem(kp.getPublic());

            byte[] der = pemToDer(originalPem);
            assertNotNull(der);
            assertTrue(der.length > 0);

            String restoredPem = derToPem(der, PemType.PUBLIC_KEY);
            // strip whitespace differences before comparing
            assertEquals(normalise(originalPem), normalise(restoredPem));
        }

        @Test
        @DisplayName("pemToDer strips headers and decodes Base64")
        void pemToDerStripsHeaders() {
            KeyPair kp = keyPair("RSA", 2048);
            byte[] expected = kp.getPublic().getEncoded();
            String pem = keyToPem(kp.getPublic());

            assertArrayEquals(expected, pemToDer(pem));
        }

        @Test
        @DisplayName("derToPem uses correct PEM label")
        void derToPemUsesCorrectLabel() {
            KeyPair kp = keyPair("RSA", 2048);
            byte[] der = kp.getPrivate().getEncoded();

            String pem = derToPem(der, PemType.PRIVATE_KEY);
            assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"), "wrong BEGIN label");
            assertTrue(pem.endsWith("-----END PRIVATE KEY-----"), "wrong END label");
        }

        @Test
        @DisplayName("pemToDer rejects null input")
        void pemToDerRejectsNull() {
            assertThrows(BruceException.class, () -> pemToDer(null));
        }

        @Test
        @DisplayName("pemToDer rejects blank input")
        void pemToDerRejectsBlank() {
            assertThrows(BruceException.class, () -> pemToDer("   "));
        }
    }

    // ── PKCS#1 RSA private key ─────────────────────────────────────────────────

    @Nested
    @DisplayName("PKCS#1 RSA private key")
    class Pkcs1PrivateKey {

        @Test
        @DisplayName("PKCS#8 → PKCS#1 DER → restore: yields same key")
        void pkcs8ToPkcs1AndBack() {
            KeyPair kp = keyPair("RSA", 2048);
            PrivateKey original = kp.getPrivate();

            byte[] pkcs1Der = rsaPrivateKeyToPkcs1(original);
            assertNotNull(pkcs1Der);
            assertTrue(pkcs1Der.length > 0);

            PrivateKey restored = rsaPrivateKeyFromPkcs1(pkcs1Der);
            assertArrayEquals(original.getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("PKCS#1 PEM round-trip")
        void pkcs1PemRoundTrip() {
            KeyPair kp = keyPair("RSA", 2048);
            PrivateKey original = kp.getPrivate();

            String pkcs1Pem = rsaPrivateKeyToPkcs1Pem(original);
            assertTrue(pkcs1Pem.startsWith("-----BEGIN RSA PRIVATE KEY-----"),
                    "expected RSA PRIVATE KEY header");
            assertTrue(pkcs1Pem.endsWith("-----END RSA PRIVATE KEY-----"),
                    "expected RSA PRIVATE KEY footer");

            PrivateKey restored = rsaPrivateKeyFromPkcs1Pem(pkcs1Pem);
            assertArrayEquals(original.getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("PKCS#1 DER is shorter than PKCS#8 DER (no wrapper overhead)")
        void pkcs1IsSmallerThanPkcs8() {
            KeyPair kp = keyPair("RSA", 2048);
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            byte[] pkcs1 = rsaPrivateKeyToPkcs1(kp.getPrivate());
            // PKCS#8 adds the version + algorithmId + OCTET STRING wrapper
            assertTrue(pkcs1.length < pkcs8.length,
                    "PKCS#1 should be smaller than PKCS#8, but pkcs1=%d pkcs8=%d"
                            .formatted(pkcs1.length, pkcs8.length));
        }

        @Test
        @DisplayName("rsaPrivateKeyToPkcs1 throws on null-encoding key")
        void rsaPrivateKeyToPkcs1ThrowsOnNullEncoding() {
            assertThrows(BruceException.class,
                    () -> rsaPrivateKeyToPkcs1(new NoEncodingPrivateKey()));
        }

        @Test
        @DisplayName("rsaPrivateKeyFromPkcs1 throws on invalid DER bytes")
        void rsaPrivateKeyFromPkcs1ThrowsOnInvalidBytes() {
            // 128 garbage bytes: triggers encodeLength 128-255 branch and then
            // InvalidKeySpecException when the JDK rejects the wrapped garbage as RSA
            assertThrows(BruceException.class, () -> rsaPrivateKeyFromPkcs1(new byte[128]));
        }

        @Test
        @DisplayName("rsaPrivateKeyToPkcs1 throws on truncated PKCS#8 encoding")
        void rsaPrivateKeyToPkcs1ThrowsOnTruncatedPkcs8() {
            // 0x30 0x00 is a valid SEQUENCE tag but an empty body; parsing fails
            assertThrows(BruceException.class,
                    () -> rsaPrivateKeyToPkcs1(new StubPrivateKey(new byte[]{0x30, 0x00})));
        }

        @Test
        @DisplayName("rsaPrivateKeyToPkcs1 throws on wrong outer DER tag")
        void rsaPrivateKeyToPkcs1ThrowsOnWrongOuterTag() {
            // 0x04 is OCTET STRING, not the expected SEQUENCE (0x30)
            assertThrows(BruceException.class,
                    () -> rsaPrivateKeyToPkcs1(new StubPrivateKey(new byte[]{0x04, 0x01, 0x00})));
        }

        @Test
        @DisplayName("rsaPrivateKeyToPkcs1 throws when OCTET STRING tag is missing in PKCS#8")
        void rsaPrivateKeyToPkcs1ThrowsOnMissingOctetString() {
            // Valid SEQUENCE containing version INTEGER + algorithmId SEQUENCE,
            // but BIT STRING (0x03) where OCTET STRING (0x04) is expected
            byte[] crafted = {0x30, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x02, 0x05, 0x00, 0x03, 0x01, 0x00};
            assertThrows(BruceException.class,
                    () -> rsaPrivateKeyToPkcs1(new StubPrivateKey(crafted)));
        }
    }

    // ── PKCS#1 RSA public key ─────────────────────────────────────────────────

    @Nested
    @DisplayName("PKCS#1 RSA public key")
    class Pkcs1PublicKey {

        @Test
        @DisplayName("SPKI → PKCS#1 DER → restore: yields same key")
        void spkiToPkcs1AndBack() {
            KeyPair kp = keyPair("RSA", 2048);
            PublicKey original = kp.getPublic();

            byte[] pkcs1Der = rsaPublicKeyToPkcs1(original);
            assertNotNull(pkcs1Der);
            assertTrue(pkcs1Der.length > 0);

            PublicKey restored = rsaPublicKeyFromPkcs1(pkcs1Der);
            assertArrayEquals(original.getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("PKCS#1 PEM round-trip")
        void pkcs1PemRoundTrip() {
            KeyPair kp = keyPair("RSA", 2048);
            PublicKey original = kp.getPublic();

            String pkcs1Pem = rsaPublicKeyToPkcs1Pem(original);
            assertTrue(pkcs1Pem.startsWith("-----BEGIN RSA PUBLIC KEY-----"),
                    "expected RSA PUBLIC KEY header");
            assertTrue(pkcs1Pem.endsWith("-----END RSA PUBLIC KEY-----"),
                    "expected RSA PUBLIC KEY footer");

            PublicKey restored = rsaPublicKeyFromPkcs1Pem(pkcs1Pem);
            assertArrayEquals(original.getEncoded(), restored.getEncoded());
        }

        @Test
        @DisplayName("PKCS#1 DER is shorter than SPKI DER (no wrapper overhead)")
        void pkcs1IsSmallerThanSpki() {
            KeyPair kp = keyPair("RSA", 2048);
            byte[] spki = kp.getPublic().getEncoded();
            byte[] pkcs1 = rsaPublicKeyToPkcs1(kp.getPublic());
            assertTrue(pkcs1.length < spki.length,
                    "PKCS#1 should be smaller than SPKI, but pkcs1=%d spki=%d"
                            .formatted(pkcs1.length, spki.length));
        }

        @Test
        @DisplayName("rsaPublicKeyToPkcs1 throws on null-encoding key")
        void rsaPublicKeyToPkcs1ThrowsOnNullEncoding() {
            assertThrows(BruceException.class,
                    () -> rsaPublicKeyToPkcs1(new NoEncodingPublicKey()));
        }

        @Test
        @DisplayName("rsaPublicKeyFromPkcs1 throws on empty DER bytes")
        void rsaPublicKeyFromPkcs1ThrowsOnEmptyBytes() {
            // empty pkcs1: buildBitString adds 1 byte → encodeLength(1) hits the
            // short-form (< 128) branch, then generatePublic rejects the wrapped garbage
            assertThrows(BruceException.class, () -> rsaPublicKeyFromPkcs1(new byte[0]));
        }

        @Test
        @DisplayName("rsaPublicKeyFromPkcs1 throws on invalid DER bytes")
        void rsaPublicKeyFromPkcs1ThrowsOnInvalidBytes() {
            // 127 garbage bytes: buildBitString adds 1 → encodeLength(128) hits
            // the 128-255 branch, then generatePublic rejects the wrapped garbage
            assertThrows(BruceException.class, () -> rsaPublicKeyFromPkcs1(new byte[127]));
        }

        @Test
        @DisplayName("rsaPublicKeyToPkcs1 throws on truncated SPKI encoding")
        void rsaPublicKeyToPkcs1ThrowsOnTruncatedSpki() {
            assertThrows(BruceException.class,
                    () -> rsaPublicKeyToPkcs1(new StubPublicKey(new byte[]{0x30, 0x00})));
        }

        @Test
        @DisplayName("rsaPublicKeyToPkcs1 throws on wrong outer DER tag")
        void rsaPublicKeyToPkcs1ThrowsOnWrongOuterTag() {
            assertThrows(BruceException.class,
                    () -> rsaPublicKeyToPkcs1(new StubPublicKey(new byte[]{0x04, 0x01, 0x00})));
        }

        @Test
        @DisplayName("rsaPublicKeyToPkcs1 throws when BIT STRING tag is missing in SPKI")
        void rsaPublicKeyToPkcs1ThrowsOnMissingBitString() {
            // Valid SEQUENCE + algorithmId SEQUENCE, but OCTET STRING (0x04) where
            // BIT STRING (0x03) is expected
            byte[] crafted = {0x30, 0x07, 0x30, 0x02, 0x05, 0x00, 0x04, 0x01, 0x00};
            assertThrows(BruceException.class,
                    () -> rsaPublicKeyToPkcs1(new StubPublicKey(crafted)));
        }

        @Test
        @DisplayName("rsaPublicKeyToPkcs1 throws on BIT STRING with non-zero unused bits")
        void rsaPublicKeyToPkcs1ThrowsOnNonZeroUnusedBits() {
            // BIT STRING value byte 0x01 (non-zero unused bits count) is invalid DER
            byte[] crafted = {0x30, 0x08, 0x30, 0x02, 0x05, 0x00, 0x03, 0x02, 0x01, 0x00};
            assertThrows(BruceException.class,
                    () -> rsaPublicKeyToPkcs1(new StubPublicKey(crafted)));
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static String normalise(String pem) {
        return pem.replaceAll("\\s+", "");
    }

    /** Stub key that returns null from getEncoded(). */
    private static final class NoEncodingKey implements java.security.Key {
        @Override public String getAlgorithm() { return "NONE"; }
        @Override public String getFormat()    { return null; }
        @Override public byte[] getEncoded()   { return null; }
    }

    private static final class NoEncodingPrivateKey implements PrivateKey {
        @Override public String getAlgorithm() { return "NONE"; }
        @Override public String getFormat()    { return null; }
        @Override public byte[] getEncoded()   { return null; }
    }

    private static final class NoEncodingPublicKey implements PublicKey {
        @Override public String getAlgorithm() { return "NONE"; }
        @Override public String getFormat()    { return null; }
        @Override public byte[] getEncoded()   { return null; }
    }

    /** Stub private key that returns a fixed byte array from getEncoded(). */
    private static final class StubPrivateKey implements PrivateKey {
        private final byte[] encoding;
        StubPrivateKey(byte[] encoding) { this.encoding = encoding; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat()    { return "PKCS#8"; }
        @Override public byte[] getEncoded()   { return encoding; }
    }

    /** Stub public key that returns a fixed byte array from getEncoded(). */
    private static final class StubPublicKey implements PublicKey {
        private final byte[] encoding;
        StubPublicKey(byte[] encoding) { this.encoding = encoding; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat()    { return "X.509"; }
        @Override public byte[] getEncoded()   { return encoding; }
    }

    /** Stub certificate whose getEncoded() always throws CertificateEncodingException. */
    private static final class FailingCertificate extends Certificate {
        FailingCertificate() { super("TEST"); }
        @Override public byte[] getEncoded() throws CertificateEncodingException {
            throw new CertificateEncodingException("simulated encoding failure");
        }
        @Override public void verify(PublicKey key)
                throws CertificateException, NoSuchAlgorithmException,
                       InvalidKeyException, NoSuchProviderException, SignatureException {}
        @Override public void verify(PublicKey key, String sigProvider)
                throws CertificateException, NoSuchAlgorithmException,
                       InvalidKeyException, NoSuchProviderException, SignatureException {}
        @Override public String toString()     { return "FailingCertificate"; }
        @Override public PublicKey getPublicKey() { return null; }
    }
}
