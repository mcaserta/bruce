package com.mirkocaserta.bruce.impl.mac;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static com.mirkocaserta.bruce.Keystores.symmetricKey;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MacOperationsTest {

    @Test
    void noSuchAlgorithmIsWrapped() {
        SecretKey secretKey = new SecretKeySpec(symmetricKey("HmacSHA256"), "HmacSHA256");
        var invalidAlgorithmMac = MacOperations.createMac(secretKey, "NO_SUCH_MAC");
        assertThrows(BruceException.class, () -> invalidAlgorithmMac.get("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void encodingMacWorks() {
        SecretKey secretKey = new SecretKeySpec(symmetricKey("HmacSHA256"), "HmacSHA256");
        var mac = MacOperations.createEncodingMac(secretKey, "HmacSHA256", Bruce.Encoding.BASE64, StandardCharsets.UTF_8);

        String first = mac.get("mac-payload");
        String second = mac.get("mac-payload-2");

        assertNotEquals(first, second);
        assertTrue(Base64.getDecoder().decode(first).length > 0);
    }
}

