package com.mirkocaserta.bruce;

import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BruceNestedEnumAndKeystoreOverloadsTest {

    @Test
    void nestedAlgorithmEnumsExposeNonBlankAlgorithmNames() {
        for (Bruce.DigestAlgorithm a : Bruce.DigestAlgorithm.values()) {
            assertNotNull(a.algorithmName());
            assertFalse(a.algorithmName().isBlank());
        }
        for (Bruce.MacAlgorithm a : Bruce.MacAlgorithm.values()) {
            assertNotNull(a.algorithmName());
            assertFalse(a.algorithmName().isBlank());
        }
        for (Bruce.SignatureAlgorithm a : Bruce.SignatureAlgorithm.values()) {
            assertNotNull(a.algorithmName());
            assertFalse(a.algorithmName().isBlank());
        }
        for (Bruce.AsymmetricKeyAlgorithm a : Bruce.AsymmetricKeyAlgorithm.values()) {
            assertNotNull(a.algorithmName());
            assertFalse(a.algorithmName().isBlank());
        }
        for (Bruce.SymmetricKeyAlgorithm a : Bruce.SymmetricKeyAlgorithm.values()) {
            assertNotNull(a.algorithmName());
            assertFalse(a.algorithmName().isBlank());
        }
        for (Bruce.CipherAlgorithm a : Bruce.CipherAlgorithm.values()) {
            assertNotNull(a.algorithmName());
            assertFalse(a.algorithmName().isBlank());
        }
    }

    @Test
    void keystoreNestedEnumOverloadsGenerateKeysAcrossSignatures() throws Exception {
        var random = SecureRandom.getInstanceStrong();

        assertNotNull(Keystores.keyPair(Bruce.AsymmetricKeyAlgorithm.RSA, 1024));
        assertNotNull(Keystores.keyPair(Bruce.AsymmetricKeyAlgorithm.RSA, "", 1024));
        assertNotNull(Keystores.keyPair(Bruce.AsymmetricKeyAlgorithm.RSA, Bruce.Provider.JCA, 1024));

        assertNotNull(Keystores.keyPair(Bruce.AsymmetricKeyAlgorithm.RSA, 1024, random));
        assertNotNull(Keystores.keyPair(Bruce.AsymmetricKeyAlgorithm.RSA, "", 1024, random));
        assertNotNull(Keystores.keyPair(Bruce.AsymmetricKeyAlgorithm.RSA, Bruce.Provider.JCA, 1024, random));

        assertTrue(Keystores.symmetricKey(Bruce.SymmetricKeyAlgorithm.AES).length > 0);
        assertTrue(Keystores.symmetricKey(Bruce.SymmetricKeyAlgorithm.AES, "").length > 0);
        assertTrue(Keystores.symmetricKey(Bruce.SymmetricKeyAlgorithm.AES, Bruce.Provider.JCA).length > 0);

        assertFalse(Keystores.symmetricKey(Bruce.SymmetricKeyAlgorithm.AES, BASE64).isBlank());
        assertFalse(Keystores.symmetricKey(Bruce.SymmetricKeyAlgorithm.AES, "", BASE64).isBlank());
        assertFalse(Keystores.symmetricKey(Bruce.SymmetricKeyAlgorithm.AES, Bruce.Provider.JCA, BASE64).isBlank());
    }

    @Test
    void keystorePemAndEncodingErrorPathsAreWrapped() {
        assertThrows(BruceException.class, () -> Keystores.privateKeyFromPem("not-a-pem", "RSA"));
        assertThrows(BruceException.class, () -> Keystores.publicKeyFromPem("not-a-pem", "RSA"));
        assertThrows(BruceException.class, () -> Keystores.certificateFromPem("not-a-pem"));

        Key noEncodingKey = new Key() {
            @Override
            public String getAlgorithm() {
                return "AES";
            }

            @Override
            public String getFormat() {
                return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }
        };
        assertThrows(BruceException.class, () -> Keystores.keyToPem(noEncodingKey));

        Certificate brokenCertificate = new Certificate("X.509") {
            @Override
            public byte[] getEncoded() throws CertificateEncodingException {
                throw new CertificateEncodingException("boom");
            }

            @Override
            public void verify(PublicKey key) {
                // not needed for this test
            }

            @Override
            public void verify(PublicKey key, String sigProvider) {
                // not needed for this test
            }

            @Override
            public String toString() {
                return "broken";
            }

            @Override
            public PublicKey getPublicKey() {
                return null;
            }
        };
        assertThrows(BruceException.class, () -> Keystores.certificateToPem(brokenCertificate));
    }
}

