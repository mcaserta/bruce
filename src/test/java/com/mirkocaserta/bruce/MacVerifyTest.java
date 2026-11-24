package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.mac.Mac;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static org.junit.jupiter.api.Assertions.*;

class MacVerifyTest {

    private static final Key KEY = new SecretKeySpec(
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), "HmacSHA256");

    private static final Bytes MESSAGE = Bytes.from("Hi Bob");

    private static Mac hmacSha256() {
        return Bruce.macBuilder().key(KEY).algorithm(MacAlgorithm.HMAC_SHA_256).build();
    }

    @Test
    void correctTagVerifies() {
        Mac mac = hmacSha256();
        Bytes tag = mac.get(MESSAGE);
        assertTrue(mac.verify(MESSAGE, tag));
    }

    @Test
    void tagRestoredFromEncodedStringVerifies() {
        Mac mac = hmacSha256();
        String transported = mac.get(MESSAGE).encode(BASE64);
        assertTrue(mac.verify(MESSAGE, Bytes.from(transported, BASE64)));
    }

    @Test
    void tagForDifferentMessageIsRejected() {
        Mac mac = hmacSha256();
        Bytes tag = mac.get(Bytes.from("Hi Alice"));
        assertFalse(mac.verify(MESSAGE, tag));
    }

    @Test
    void tagWithSingleFlippedBitIsRejected() {
        Mac mac = hmacSha256();
        byte[] raw = mac.get(MESSAGE).asBytes();
        for (int i = 0; i < raw.length * 8; i++) {
            byte[] tampered = raw.clone();
            tampered[i / 8] ^= (byte) (1 << (i % 8));
            assertFalse(mac.verify(MESSAGE, Bytes.from(tampered)), "bit " + i + " flipped");
        }
    }

    @Test
    void truncatedTagIsRejected() {
        Mac mac = hmacSha256();
        byte[] raw = mac.get(MESSAGE).asBytes();
        assertFalse(mac.verify(MESSAGE, Bytes.from(Arrays.copyOf(raw, raw.length - 1))));
    }

    @Test
    void extendedTagIsRejected() {
        Mac mac = hmacSha256();
        byte[] raw = mac.get(MESSAGE).asBytes();
        assertFalse(mac.verify(MESSAGE, Bytes.from(Arrays.copyOf(raw, raw.length + 1))));
    }

    @Test
    void emptyTagIsRejected() {
        assertFalse(hmacSha256().verify(MESSAGE, Bytes.from(new byte[0])));
    }

    @Test
    void tagFromDifferentKeyIsRejected() {
        Key otherKey = new SecretKeySpec(
                "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Bytes tag = Bruce.macBuilder().key(otherKey).algorithm("HmacSHA256").build().get(MESSAGE);
        assertFalse(hmacSha256().verify(MESSAGE, tag));
    }

    @Test
    void verifyWorksWithStringAlgorithm() {
        Mac mac = Bruce.macBuilder().key(KEY).algorithm("HmacSHA256").build();
        Bytes tag = mac.get(MESSAGE);
        assertTrue(mac.verify(MESSAGE, tag));
        assertFalse(mac.verify(Bytes.from("tampered"), tag));
    }

    @ParameterizedTest
    @EnumSource(MacAlgorithm.class)
    void verifyWorksWithEveryEnumAlgorithm(MacAlgorithm algorithm) {
        Mac mac = Macs.builder().key(KEY).algorithm(algorithm).build();
        Bytes tag = mac.get(MESSAGE);
        assertTrue(mac.verify(MESSAGE, tag));
        assertFalse(mac.verify(Bytes.from("tampered"), tag));
    }

    @Test
    void separatelyBuiltMacsAgree() {
        Mac alice = hmacSha256();
        Mac bob = Bruce.macBuilder().key(KEY).algorithm("HmacSHA256").build();
        assertTrue(bob.verify(MESSAGE, alice.get(MESSAGE)));
    }

    @Test
    void verifyIsAvailableOnLambdaImplementations() {
        Mac constant = message -> Bytes.from(new byte[]{1, 2, 3});
        assertTrue(constant.verify(MESSAGE, Bytes.from(new byte[]{1, 2, 3})));
        assertFalse(constant.verify(MESSAGE, Bytes.from(new byte[]{1, 2, 4})));
    }

    @Test
    void nullTagIsRejected() {
        Mac mac = hmacSha256();
        BruceException e = assertThrows(BruceException.class, () -> mac.verify(MESSAGE, null));
        assertEquals("tag must not be null", e.getMessage());
    }

    @Test
    void nullMessageIsRejected() {
        Mac mac = hmacSha256();
        Bytes tag = mac.get(MESSAGE);
        BruceException e = assertThrows(BruceException.class, () -> mac.verify(null, tag));
        assertEquals("message must not be null", e.getMessage());
    }
}
