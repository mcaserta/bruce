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
 * wrapping or unwrapping the ASN.1 envelope, without relying on
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
 * @author Mirko Caserta (info@mirkocaserta.com)
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

    private static final String SEQUENCE = "SEQUENCE";

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
            requireInput(pkcs8Der);
            Tlv outer = readTlv(pkcs8Der, 0, pkcs8Der.length);
            requireTag(outer, 0x30, SEQUENCE);
            requireNoTrailingData(outer, pkcs8Der);
            Tlv version = readTlv(pkcs8Der, outer.valueStart(), outer.end());
            requireTag(version, 0x02, "INTEGER");
            Tlv algorithmId = readTlv(pkcs8Der, version.end(), outer.end());
            requireRsaAlgorithm(pkcs8Der, algorithmId);
            Tlv octetString = readTlv(pkcs8Der, algorithmId.end(), outer.end());
            requireTag(octetString, 0x04, "OCTET STRING");
            return Arrays.copyOfRange(pkcs8Der, octetString.valueStart(), octetString.end());
        } catch (BruceException e) {
            throw new BruceException("invalid PKCS#8 structure: " + e.getMessage(), e);
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
            requireInput(spkiDer);
            Tlv outer = readTlv(spkiDer, 0, spkiDer.length);
            requireTag(outer, 0x30, SEQUENCE);
            requireNoTrailingData(outer, spkiDer);
            Tlv algorithmId = readTlv(spkiDer, outer.valueStart(), outer.end());
            requireRsaAlgorithm(spkiDer, algorithmId);
            Tlv bitString = readTlv(spkiDer, algorithmId.end(), outer.end());
            requireTag(bitString, 0x03, "BIT STRING");
            if (bitString.length() == 0) {
                throw new BruceException("BIT STRING is empty (missing unused-bits byte)");
            }
            // first byte is unused-bits count; for DER-encoded keys it must be 0x00
            int unusedBits = spkiDer[bitString.valueStart()] & 0xFF;
            if (unusedBits != 0) {
                throw new BruceException("BIT STRING has non-zero unused-bits byte: " + unusedBits);
            }
            return Arrays.copyOfRange(spkiDer, bitString.valueStart() + 1, bitString.end());
        } catch (BruceException e) {
            throw new BruceException("invalid SubjectPublicKeyInfo structure: " + e.getMessage(), e);
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
     * A decoded DER tag-length-value header.
     *
     * @param tag        the single-byte tag
     * @param valueStart index of the first value byte
     * @param length     number of value bytes
     */
    private record Tlv(int tag, int valueStart, int length) {
        /** Index just past the last value byte. */
        int end() {
            return valueStart + length;
        }
    }

    private static void requireInput(byte[] der) {
        if (der == null) {
            throw new BruceException("input is null");
        }
    }

    private static void requireNoTrailingData(Tlv outer, byte[] der) {
        if (outer.end() != der.length) {
            throw new BruceException("%d trailing bytes after the outer SEQUENCE"
                    .formatted(der.length - outer.end()));
        }
    }

    /**
     * Checks that an AlgorithmIdentifier names rsaEncryption, so an EC or DSA
     * key is not passed off as PKCS#1 RSA.
     */
    private static void requireRsaAlgorithm(byte[] der, Tlv algorithmId) {
        requireTag(algorithmId, 0x30, SEQUENCE);
        Tlv oid = readTlv(der, algorithmId.valueStart(), algorithmId.end());
        requireTag(oid, 0x06, "OBJECT IDENTIFIER");
        // RSA_ALGORITHM_IDENTIFIER is 30 0d | 06 09 <oid> | 05 00: the OID TLV starts at index 2
        int expectedLength = RSA_ALGORITHM_IDENTIFIER[3];
        boolean rsa = oid.length() == expectedLength && Arrays.equals(
                der, oid.valueStart(), oid.end(),
                RSA_ALGORITHM_IDENTIFIER, 4, 4 + expectedLength);
        if (!rsa) {
            throw new BruceException("key is not an RSA key (algorithm is not rsaEncryption)");
        }
    }

    private static void requireTag(Tlv tlv, int expectedTag, String name) {
        if (tlv.tag() != expectedTag) {
            throw new BruceException("expected %s (0x%02x), got tag 0x%02x"
                    .formatted(name, expectedTag, tlv.tag()));
        }
    }

    /**
     * Reads the TLV header at {@code pos}, ensuring the header and the whole
     * value lie within {@code [pos, limit)}. {@code limit} is the end of the
     * enclosing structure (or of the input).
     */
    private static Tlv readTlv(byte[] der, int pos, int limit) {
        if (pos < 0 || pos >= limit) {
            throw new BruceException("unexpected end of DER data at pos %d".formatted(pos));
        }
        int tag = der[pos] & 0xFF;
        int lenPos = pos + 1;
        int len = readLength(der, lenPos, limit);
        int valueStart = lenPos + lengthFieldSize(der, lenPos, limit);
        if ((long) valueStart + len > limit) {
            throw new BruceException("DER value of tag 0x%02x at pos %d has length %d, exceeding available %d bytes"
                    .formatted(tag, pos, len, limit - valueStart));
        }
        return new Tlv(tag, valueStart, len);
    }

    /**
     * Reads the DER length field starting at {@code pos} (multi-byte form supported).
     *
     * @throws BruceException if the length field is truncated, uses the
     *                        indefinite form, has more than 4 length bytes,
     *                        or encodes a value that does not fit in a non-negative int
     */
    static int readLength(byte[] data, int pos) {
        return readLength(data, pos, data.length);
    }

    private static int readLength(byte[] data, int pos, int limit) {
        int numBytes = lengthFieldSize(data, pos, limit) - 1;
        if (numBytes == 0) {
            return data[pos] & 0xFF;
        }
        long length = 0;
        for (int i = 1; i <= numBytes; i++) {
            length = (length << 8) | (data[pos + i] & 0xFF);
        }
        if (length > Integer.MAX_VALUE) {
            throw new BruceException("DER length %d at pos %d is too large".formatted(length, pos));
        }
        return (int) length;
    }

    /**
     * Returns the number of bytes used by the length field at {@code pos}.
     *
     * @throws BruceException if the length field is truncated, uses the
     *                        indefinite form, or has more than 4 length bytes
     */
    static int lengthFieldSize(byte[] data, int pos) {
        return lengthFieldSize(data, pos, data.length);
    }

    private static int lengthFieldSize(byte[] data, int pos, int limit) {
        if (pos < 0 || pos >= limit) {
            throw new BruceException("unexpected end of DER data reading length at pos %d".formatted(pos));
        }
        int b = data[pos] & 0xFF;
        if (b < 0x80) {
            return 1;
        }
        int numBytes = b & 0x7F;
        if (numBytes == 0) {
            throw new BruceException("indefinite DER length at pos %d is not allowed".formatted(pos));
        }
        if (numBytes > 4) {
            throw new BruceException("DER length field at pos %d uses %d bytes (max 4)".formatted(pos, numBytes));
        }
        if ((long) pos + numBytes >= limit) {
            throw new BruceException("truncated DER length field at pos %d".formatted(pos));
        }
        return 1 + numBytes;
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

    /**
     * Encodes a DER length using the minimal definite form (short form below
     * 128, otherwise 0x81..0x84 followed by 1 to 4 big-endian bytes).
     */
    static byte[] encodeLength(int length) {
        if (length < 0) {
            throw new BruceException("negative DER length: " + length);
        }
        if (length < 0x80) {
            return new byte[]{(byte) length};
        }
        int numBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
        byte[] result = new byte[1 + numBytes];
        result[0] = (byte) (0x80 | numBytes);
        for (int i = 0; i < numBytes; i++) {
            result[numBytes - i] = (byte) (length >>> (8 * i));
        }
        return result;
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
