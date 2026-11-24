package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class Pkcs1UtilsTest {

    private static KeyPair rsa;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsa = kpg.generateKeyPair();
    }

    // ── valid round trips ─────────────────────────────────────────────────────

    @Test
    void privateKeyRoundTrip() {
        byte[] pkcs8 = rsa.getPrivate().getEncoded();
        byte[] pkcs1 = Pkcs1Utils.pkcs8ToPkcs1PrivateKey(pkcs8);
        assertArrayEquals(pkcs8, Pkcs1Utils.pkcs1ToPkcs8(pkcs1));
        assertEquals(rsa.getPrivate(), Pkcs1Utils.rsaPrivateKeyFromPkcs1(pkcs1));
    }

    @Test
    void publicKeyRoundTrip() {
        byte[] spki = rsa.getPublic().getEncoded();
        byte[] pkcs1 = Pkcs1Utils.spkiToPkcs1PublicKey(spki);
        assertArrayEquals(spki, Pkcs1Utils.pkcs1ToSpki(pkcs1));
        assertEquals(rsa.getPublic(), Pkcs1Utils.rsaPublicKeyFromPkcs1(pkcs1));
    }

    @Test
    void largeContentRoundTripsThroughPkcs8() {
        byte[] content = new byte[70_000];
        for (int i = 0; i < content.length; i++) content[i] = (byte) i;
        byte[] pkcs8 = Pkcs1Utils.pkcs1ToPkcs8(content);
        // outer SEQUENCE must use the three-byte long form (0x83)
        assertEquals((byte) 0x83, pkcs8[1]);
        assertEquals(pkcs8.length - 5, Pkcs1Utils.readLength(pkcs8, 1));
        assertArrayEquals(content, Pkcs1Utils.pkcs8ToPkcs1PrivateKey(pkcs8));
    }

    @Test
    void largeContentRoundTripsThroughSpki() {
        byte[] content = new byte[70_000];
        Arrays.fill(content, (byte) 0x5a);
        byte[] spki = Pkcs1Utils.pkcs1ToSpki(content);
        assertArrayEquals(content, Pkcs1Utils.spkiToPkcs1PublicKey(spki));
    }

    @Test
    void encodeLengthUsesMinimalForms() {
        assertArrayEquals(new byte[]{0x00}, Pkcs1Utils.encodeLength(0));
        assertArrayEquals(new byte[]{0x7f}, Pkcs1Utils.encodeLength(127));
        assertArrayEquals(new byte[]{(byte) 0x81, (byte) 0x80}, Pkcs1Utils.encodeLength(128));
        assertArrayEquals(new byte[]{(byte) 0x81, (byte) 0xff}, Pkcs1Utils.encodeLength(255));
        assertArrayEquals(new byte[]{(byte) 0x82, 0x01, 0x00}, Pkcs1Utils.encodeLength(256));
        assertArrayEquals(new byte[]{(byte) 0x82, (byte) 0xff, (byte) 0xff}, Pkcs1Utils.encodeLength(65_535));
        assertArrayEquals(new byte[]{(byte) 0x83, 0x01, 0x00, 0x00}, Pkcs1Utils.encodeLength(65_536));
        assertArrayEquals(new byte[]{(byte) 0x83, 0x01, 0x11, 0x70}, Pkcs1Utils.encodeLength(70_000));
        assertArrayEquals(new byte[]{(byte) 0x83, (byte) 0xff, (byte) 0xff, (byte) 0xff},
                Pkcs1Utils.encodeLength(0xff_ffff));
        assertArrayEquals(new byte[]{(byte) 0x84, 0x01, 0x00, 0x00, 0x00}, Pkcs1Utils.encodeLength(0x100_0000));
        assertArrayEquals(new byte[]{(byte) 0x84, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff},
                Pkcs1Utils.encodeLength(Integer.MAX_VALUE));
        assertThrows(BruceException.class, () -> Pkcs1Utils.encodeLength(-1));
    }

    @Test
    void encodeLengthRoundTripsThroughReadLength() {
        int[] lengths = {0, 1, 127, 128, 255, 256, 65_535, 65_536, 70_000, 0xff_ffff, 0x100_0000, Integer.MAX_VALUE};
        for (int len : lengths) {
            byte[] enc = Pkcs1Utils.encodeLength(len);
            assertEquals(len, Pkcs1Utils.readLength(enc, 0), "length " + len);
            assertEquals(enc.length, Pkcs1Utils.lengthFieldSize(enc, 0), "length " + len);
        }
    }

    // ── truncated input ───────────────────────────────────────────────────────

    @Test
    void truncatedPkcs8IsRejected() {
        byte[] pkcs8 = rsa.getPrivate().getEncoded();
        for (int cut : new int[]{0, 1, 2, 4, 10, 30, pkcs8.length / 2, pkcs8.length - 1}) {
            byte[] truncated = Arrays.copyOf(pkcs8, cut);
            assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(truncated),
                    "cut at " + cut);
        }
    }

    @Test
    void truncatedSpkiIsRejected() {
        byte[] spki = rsa.getPublic().getEncoded();
        for (int cut : new int[]{0, 1, 2, 4, 10, 20, spki.length / 2, spki.length - 1}) {
            byte[] truncated = Arrays.copyOf(spki, cut);
            assertThrows(BruceException.class, () -> Pkcs1Utils.spkiToPkcs1PublicKey(truncated),
                    "cut at " + cut);
        }
    }

    @Test
    void octetStringPastEndOfInputIsRejected() {
        // SEQUENCE { INTEGER 0, SEQUENCE {}, OCTET STRING len=10 but only 2 bytes }
        byte[] der = {0x30, 0x09, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04, 0x0a, 0x01, 0x02};
        BruceException e = assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
        assertTrue(e.getMessage().contains("PKCS#8"), e.getMessage());
    }

    @Test
    void innerTlvPastEndOfEnclosingSequenceIsRejected() {
        // outer SEQUENCE claims 3 bytes but the OCTET STRING extends further
        byte[] der = {0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04, 0x01, 0x01};
        assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
    }

    @Test
    void outerSequencePastEndOfInputIsRejected() {
        byte[] der = {0x30, 0x7f, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04, 0x01, 0x01};
        assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
    }

    // ── malformed lengths ─────────────────────────────────────────────────────

    @Test
    void hugeLengthIsRejected() {
        // OCTET STRING length 0x84 FFFFFFFF (negative as int)
        byte[] der = {0x30, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04,
                (byte) 0x84, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
        assertThrows(BruceException.class,
                () -> Pkcs1Utils.readLength(new byte[]{(byte) 0x84, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}, 0));
    }

    @Test
    void hugePositiveLengthIsRejected() {
        // OCTET STRING claims 0x7fffffff bytes
        byte[] der = {0x30, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04,
                (byte) 0x84, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
    }

    @Test
    void hugeLengthInSkippedTlvIsRejected() {
        // version INTEGER with huge length: skipTlv must not overflow
        byte[] der = {0x30, 0x06, 0x02, (byte) 0x84, 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
    }

    @Test
    void indefiniteLengthIsRejected() {
        byte[] der = {0x30, (byte) 0x80, 0x02, 0x01, 0x00, 0x00, 0x00};
        BruceException e = assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(der));
        assertTrue(e.getMessage().contains("PKCS#8"), e.getMessage());
        assertThrows(BruceException.class, () -> Pkcs1Utils.readLength(new byte[]{(byte) 0x80}, 0));
        assertThrows(BruceException.class, () -> Pkcs1Utils.lengthFieldSize(new byte[]{(byte) 0x80}, 0));
    }

    @Test
    void lengthFieldLongerThanFourBytesIsRejected() {
        byte[] der = {0x30, (byte) 0x85, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02, 0x01, 0x00, 0x30, 0x00};
        assertThrows(BruceException.class, () -> Pkcs1Utils.spkiToPkcs1PublicKey(der));
        assertThrows(BruceException.class,
                () -> Pkcs1Utils.readLength(new byte[]{(byte) 0x85, 0, 0, 0, 0, 1}, 0));
        assertThrows(BruceException.class,
                () -> Pkcs1Utils.lengthFieldSize(new byte[]{(byte) 0x85, 0, 0, 0, 0, 1}, 0));
    }

    @Test
    void lengthFieldTruncatedIsRejected() {
        assertThrows(BruceException.class, () -> Pkcs1Utils.readLength(new byte[]{(byte) 0x82, 0x01}, 0));
        assertThrows(BruceException.class, () -> Pkcs1Utils.readLength(new byte[]{}, 0));
        assertThrows(BruceException.class, () -> Pkcs1Utils.lengthFieldSize(new byte[]{(byte) 0x82, 0x01}, 0));
    }

    // ── BIT STRING edge cases ─────────────────────────────────────────────────

    @Test
    void emptyBitStringIsRejected() {
        // SEQUENCE { SEQUENCE {}, BIT STRING len=0 }
        byte[] der = {0x30, 0x04, 0x30, 0x00, 0x03, 0x00};
        BruceException e = assertThrows(BruceException.class, () -> Pkcs1Utils.spkiToPkcs1PublicKey(der));
        assertTrue(e.getMessage().contains("SubjectPublicKeyInfo"), e.getMessage());
    }

    @Test
    void bitStringWithNonZeroUnusedBitsIsRejected() {
        byte[] der = {0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x01, 0x00};
        assertThrows(BruceException.class, () -> Pkcs1Utils.spkiToPkcs1PublicKey(der));
    }

    @Test
    void bitStringPastEndOfInputIsRejected() {
        byte[] der = {0x30, 0x06, 0x30, 0x00, 0x03, 0x10, 0x00, 0x00};
        assertThrows(BruceException.class, () -> Pkcs1Utils.spkiToPkcs1PublicKey(der));
    }

    // ── wrong tags and null ───────────────────────────────────────────────────

    @Test
    void wrongTagsAreRejected() {
        assertThrows(BruceException.class,
                () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(new byte[]{0x31, 0x00}));
        assertThrows(BruceException.class,
                () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(new byte[]{0x30, 0x05, 0x02, 0x01, 0x00, 0x05, 0x00}));
        assertThrows(BruceException.class,
                () -> Pkcs1Utils.spkiToPkcs1PublicKey(new byte[]{0x30, 0x04, 0x30, 0x00, 0x04, 0x00}));
    }

    @Test
    void nullInputIsRejected() {
        assertThrows(BruceException.class, () -> Pkcs1Utils.pkcs8ToPkcs1PrivateKey(null));
        assertThrows(BruceException.class, () -> Pkcs1Utils.spkiToPkcs1PublicKey(null));
    }

    @Test
    void garbagePkcs1IsRejected() {
        assertThrows(BruceException.class, () -> Pkcs1Utils.rsaPrivateKeyFromPkcs1(new byte[]{0x01, 0x02}));
        assertThrows(BruceException.class, () -> Pkcs1Utils.rsaPublicKeyFromPkcs1(new byte[]{0x01, 0x02}));
    }
}
