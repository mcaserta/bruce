package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.PemType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PemUtilsTest {

    private static String block(String label, byte[] body) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(body) + "\n"
                + "-----END " + label + "-----\n";
    }

    @Test
    void decodesASingleBlock() {
        assertArrayEquals(new byte[]{1, 2, 3}, PemUtils.decode(block("CERTIFICATE", new byte[]{1, 2, 3})));
    }

    @Test
    void roundTripsWithEncode() {
        var bytes = new byte[300];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) i;
        assertArrayEquals(bytes, PemUtils.decode(PemUtils.encode(PemType.CERTIFICATE, bytes)));
    }

    @Test
    void ignoresTextBeforeTheBlock() {
        var pem = "Bag Attributes\n    localKeyID: 01 02\nsubject=/CN=x\n" + block("CERTIFICATE", new byte[]{9});
        assertArrayEquals(new byte[]{9}, PemUtils.decode(pem));
    }

    @Test
    void onlyTheFirstBlockIsDecoded() {
        var pem = block("CERTIFICATE", new byte[]{1, 2, 3}) + block("PRIVATE KEY", new byte[]{4, 5, 6});
        assertArrayEquals(new byte[]{1, 2, 3}, PemUtils.decode(pem));
    }

    @Test
    void rejectsMismatchedLabels() {
        var pem = "-----BEGIN FOO-----\nAQID\n-----END BAR-----\n";
        var e = assertThrows(BruceException.class, () -> PemUtils.decode(pem));
        assertTrue(e.getMessage().contains("END"), e.getMessage());
    }

    @Test
    void rejectsMissingEnd() {
        assertThrows(BruceException.class, () -> PemUtils.decode("-----BEGIN CERTIFICATE-----\nAQID\n"));
    }

    @Test
    void rejectsInputWithoutABlock() {
        assertThrows(BruceException.class, () -> PemUtils.decode("AQID"));
    }

    @Test
    void rejectsEncapsulatedHeaders() {
        var pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "Proc-Type: 4,ENCRYPTED\n"
                + "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n"
                + "\n"
                + "AQID\n"
                + "-----END RSA PRIVATE KEY-----\n";
        var e = assertThrows(BruceException.class, () -> PemUtils.decode(pem));
        assertTrue(e.getMessage().contains("header"), e.getMessage());
    }

    @Test
    void rejectsNonBase64Characters() {
        var pem = "-----BEGIN CERTIFICATE-----\nAQ*ID\n-----END CERTIFICATE-----\n";
        assertThrows(BruceException.class, () -> PemUtils.decode(pem));
    }

    @Test
    void rejectsAnEmptyBody() {
        assertThrows(BruceException.class, () -> PemUtils.decode("-----BEGIN X-----\n-----END X-----\n"));
    }

    @Test
    void largeInputDecodesInLinearTime() {
        var body = new byte[6 * 1024 * 1024];
        var pem = block("CERTIFICATE", body);
        // The old reduce(a + b) join took about 9 s on 5 MB.
        var decoded = assertTimeoutPreemptively(Duration.ofSeconds(3), () -> PemUtils.decode(pem));
        assertEquals(body.length, decoded.length);
    }
}
