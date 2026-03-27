package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Utility methods for PKCS#1 ↔ PKCS#8/SubjectPublicKeyInfo format conversions.
 *
 * <p>The JDK's {@link KeyFactory} understands PKCS#8 (private keys) and
 * SubjectPublicKeyInfo / X.509 (public keys) but not the older PKCS#1 /
 * SEC1 "traditional" formats.  This class bridges that gap by manually
 * wrapping or unwrapping the ASN.1 envelope — without relying on
 * Bouncy Castle or any other third-party library.</p>
 *
 * <p>Supported conversions:</p>
 * <ul>
 *   <li>PKCS#1 RSA private key DER → PKCS#8 DER → {@link PrivateKey}</li>
 *   <li>PKCS#1 RSA public key DER → SubjectPublicKeyInfo DER → {@link PublicKey}</li>
 *   <li>PKCS#8 DER → PKCS#1 RSA private key DER (by unwrapping the OCTET STRING)</li>
 *   <li>SubjectPublicKeyInfo DER → PKCS#1 RSA public key DER (by unwrapping the BIT STRING)</li>
 * </ul>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Pkcs1Utils {

    /**
     * RSA algorithm identifier (OID 1.2.840.113549.1.1.1 + NULL parameters).
     * DER encoding: SEQUENCE { OID rsaEncryption, NULL }
     */
    private static final byte[] RSA_ALGORITHM_IDENTIFIER = {
            0x30, 0x0d,                                                       // SEQUENCE, 13 bytes
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
            (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,                             // OID rsaEncryption
            0x05, 0x00                                                        // NULL
    };

    private Pkcs1Utils() {
        // utility class
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Converts a PKCS#1 RSA private key DER to a Java {@link PrivateKey}.
     *
     * <p>PKCS#1 is the traditional RSA-specific format indicated by
     * {@code -----BEGIN RSA PRIVATE KEY-----} PEM headers.  This method
     * wraps the bytes in a PKCS#8 envelope so the JDK can parse them.</p>
     *
     * @param pkcs1Der raw DER bytes of a PKCS#1 RSAPrivateKey structure
     * @return the RSA {@link PrivateKey}
     * @throws BruceException if the bytes cannot be parsed
     */
    public static PrivateKey rsaPrivateKeyFromPkcs1(byte[] pkcs1Der) {
        byte[] pkcs8 = pkcs1ToPkcs8(pkcs1Der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BruceException("error loading RSA private key from PKCS#1 DER", e);
        }
    }

    /**
     * Converts a PKCS#1 RSA public key DER to a Java {@link PublicKey}.
     *
     * <p>PKCS#1 is the traditional RSA-specific public key format indicated by
     * {@code -----BEGIN RSA PUBLIC KEY-----} PEM headers.  This method
     * wraps the bytes in a SubjectPublicKeyInfo (X.509) envelope.</p>
     *
     * @param pkcs1Der raw DER bytes of a PKCS#1 RSAPublicKey structure
     * @return the RSA {@link PublicKey}
     * @throws BruceException if the bytes cannot be parsed
     */
    public static PublicKey rsaPublicKeyFromPkcs1(byte[] pkcs1Der) {
        byte[] spki = pkcs1ToSpki(pkcs1Der);
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BruceException("error loading RSA public key from PKCS#1 DER", e);
        }
    }

    /**
     * Extracts the raw PKCS#1 DER bytes from a PKCS#8 RSA private key.
     *
     * <p>The JDK encodes RSA private keys in PKCS#8 format (the output of
     * {@code privateKey.getEncoded()}).  This method strips the outer
     * PKCS#8 wrapper, returning the embedded PKCS#1 RSAPrivateKey bytes.</p>
     *
     * @param pkcs8Der PKCS#8 DER bytes (e.g. from {@link PrivateKey#getEncoded()})
     * @return PKCS#1 RSAPrivateKey DER bytes
     * @throws BruceException if the structure cannot be parsed
     */
    public static byte[] pkcs8ToPkcs1PrivateKey(byte[] pkcs8Der) {
        // PKCS#8: SEQUENCE { INTEGER(version=0), algorithmId SEQUENCE, OCTET STRING { pkcs1 } }
        try {
            int pos = 0;
            pos = skipTagAndLength(pkcs8Der, pos, 0x30); // outer SEQUENCE
            pos = skipTlv(pkcs8Der, pos);                 // version INTEGER
            pos = skipTlv(pkcs8Der, pos);                 // algorithmId SEQUENCE
            return extractOctetString(pkcs8Der, pos);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new BruceException("invalid PKCS#8 structure", e);
        }
    }

    /**
     * Extracts the raw PKCS#1 DER bytes from a SubjectPublicKeyInfo RSA public key.
     *
     * <p>The JDK encodes RSA public keys in SubjectPublicKeyInfo (SPKI/X.509) format
     * (the output of {@code publicKey.getEncoded()}).  This method strips the outer
     * SPKI wrapper, returning the embedded PKCS#1 RSAPublicKey bytes.</p>
     *
     * @param spkiDer SubjectPublicKeyInfo DER bytes (e.g. from {@link PublicKey#getEncoded()})
     * @return PKCS#1 RSAPublicKey DER bytes
     * @throws BruceException if the structure cannot be parsed
     */
    public static byte[] spkiToPkcs1PublicKey(byte[] spkiDer) {
        // SPKI: SEQUENCE { algorithmId SEQUENCE, BIT STRING { 0x00, pkcs1 } }
        try {
            int pos = 0;
            pos = skipTagAndLength(spkiDer, pos, 0x30); // outer SEQUENCE
            pos = skipTlv(spkiDer, pos);                 // algorithmId SEQUENCE
            return extractBitStringContent(spkiDer, pos);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new BruceException("invalid SubjectPublicKeyInfo structure", e);
        }
    }

    // ── DER building helpers ──────────────────────────────────────────────────

    /**
     * Wraps PKCS#1 RSA private key bytes in a PKCS#8 structure.
     */
    static byte[] pkcs1ToPkcs8(byte[] pkcs1Der) {
        // PKCS#8: SEQUENCE { INTEGER(0), algorithmId, OCTET STRING { pkcs1 } }
        byte[] version = {0x02, 0x01, 0x00};                   // INTEGER 0
        byte[] octetString = buildTlv(0x04, pkcs1Der);
        byte[] inner = concat(version, RSA_ALGORITHM_IDENTIFIER, octetString);
        return buildTlv(0x30, inner);
    }

    /**
     * Wraps PKCS#1 RSA public key bytes in SubjectPublicKeyInfo (X.509) structure.
     */
    static byte[] pkcs1ToSpki(byte[] pkcs1Der) {
        // SPKI: SEQUENCE { algorithmId, BIT STRING { 0x00, pkcs1 } }
        byte[] bitString = buildBitString(pkcs1Der);
        byte[] inner = concat(RSA_ALGORITHM_IDENTIFIER, bitString);
        return buildTlv(0x30, inner);
    }

    // ── DER parsing helpers ───────────────────────────────────────────────────

    /**
     * Checks the tag at {@code pos}, advances past the tag and length, returns
     * the new position at the start of the value.
     */
    private static int skipTagAndLength(byte[] der, int pos, int expectedTag) {
        if ((der[pos] & 0xFF) != expectedTag) {
            throw new BruceException(
                    "unexpected DER tag 0x%02x at pos %d (expected 0x%02x)"
                            .formatted(der[pos] & 0xFF, pos, expectedTag));
        }
        pos++; // skip tag
        int lenFieldSize = lengthFieldSize(der, pos);
        return pos + lenFieldSize;  // skip length, sit at start of value
    }

    /**
     * Skips an entire TLV (tag + length + value), returning the position after it.
     */
    private static int skipTlv(byte[] der, int pos) {
        pos++; // skip tag
        int len = readLength(der, pos);
        int lenFieldSize = lengthFieldSize(der, pos);
        return pos + lenFieldSize + len;
    }

    /**
     * Reads an OCTET STRING at {@code pos} and returns its contents.
     */
    private static byte[] extractOctetString(byte[] der, int pos) {
        if ((der[pos] & 0xFF) != 0x04) {
            throw new BruceException(
                    "expected OCTET STRING (0x04) at pos %d, got 0x%02x".formatted(pos, der[pos] & 0xFF));
        }
        pos++;
        int len = readLength(der, pos);
        int lenFieldSize = lengthFieldSize(der, pos);
        pos += lenFieldSize;
        return Arrays.copyOfRange(der, pos, pos + len);
    }

    /**
     * Reads a BIT STRING at {@code pos}, strips the leading unused-bits byte,
     * and returns the payload.
     */
    private static byte[] extractBitStringContent(byte[] der, int pos) {
        if ((der[pos] & 0xFF) != 0x03) {
            throw new BruceException(
                    "expected BIT STRING (0x03) at pos %d, got 0x%02x".formatted(pos, der[pos] & 0xFF));
        }
        pos++;
        int len = readLength(der, pos);
        int lenFieldSize = lengthFieldSize(der, pos);
        pos += lenFieldSize;
        // first byte is unused-bits count; for DER it must be 0x00
        if (der[pos] != 0x00) {
            throw new BruceException("BIT STRING has non-zero unused-bits byte: " + (der[pos] & 0xFF));
        }
        pos++; // skip unused-bits byte
        return Arrays.copyOfRange(der, pos, pos + len - 1);
    }

    /**
     * Reads the DER length field starting at {@code pos} (multi-byte form supported).
     */
    static int readLength(byte[] data, int pos) {
        int b = data[pos] & 0xFF;
        if (b < 128) {
            return b;
        }
        int numBytes = b & 0x7F;
        int length = 0;
        for (int i = 1; i <= numBytes; i++) {
            length = (length << 8) | (data[pos + i] & 0xFF);
        }
        return length;
    }

    /**
     * Returns the number of bytes used by the length field at {@code pos}.
     */
    static int lengthFieldSize(byte[] data, int pos) {
        int b = data[pos] & 0xFF;
        if (b < 128) return 1;
        return 1 + (b & 0x7F);
    }

    // ── Low-level DER building ────────────────────────────────────────────────

    private static byte[] buildTlv(int tag, byte[] content) {
        byte[] lengthBytes = encodeLength(content.length);
        byte[] result = new byte[1 + lengthBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lengthBytes, 0, result, 1, lengthBytes.length);
        System.arraycopy(content, 0, result, 1 + lengthBytes.length, content.length);
        return result;
    }

    private static byte[] buildBitString(byte[] content) {
        // BIT STRING value = { unused_bits=0x00, content... }
        byte[] bitContent = new byte[content.length + 1];
        bitContent[0] = 0x00;
        System.arraycopy(content, 0, bitContent, 1, content.length);
        return buildTlv(0x03, bitContent);
    }

    private static byte[] encodeLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        } else if (length < 256) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] arr : arrays) total += arr.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, pos, arr.length);
            pos += arr.length;
        }
        return result;
    }
}
