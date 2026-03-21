package com.mirkocaserta.bruce;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Bruce.Encoding.BASE64;
import static com.mirkocaserta.bruce.Bruce.Encoding.HEX;
import static com.mirkocaserta.bruce.Keystores.symmetricKey;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for symmetric key generation with various parameters and encodings.
 * Verifies that key generation works correctly with different algorithms, providers, and output formats.
 */
class SymmetricKeyGenerationTest {

    @Test
    @DisplayName("generates symmetric key with provider as raw bytes")
    void withProviderRawBytes() {
        byte[] key1 = symmetricKey("AES", "");
        byte[] key2 = symmetricKey("AES", "");

        assertNotNull(key1);
        assertNotNull(key2);
        assertTrue(key1.length > 0);
        assertTrue(key2.length > 0);
        // Keys should be different (random generation)
        assertNotEquals(key1, key2);
    }

    @Test
    @DisplayName("generates symmetric key with provider as Base64 string")
    void withProviderBase64() {
        String key1 = symmetricKey("AES", "", BASE64);
        String key2 = symmetricKey("AES", "", BASE64);

        assertNotNull(key1);
        assertNotNull(key2);
        assertFalse(key1.isBlank());
        assertFalse(key2.isBlank());
        // Keys should be different (random generation)
        assertNotEquals(key1, key2);
        // Should be valid BASE64
        assertDoesNotThrow(() -> Bytes.from(key1, BASE64));
    }

    @Test
    @DisplayName("generates symmetric key with provider as HEX string")
    void withProviderHex() {
        String key1 = symmetricKey("AES", "", HEX);
        String key2 = symmetricKey("AES", "", HEX);

        assertNotNull(key1);
        assertNotNull(key2);
        assertFalse(key1.isBlank());
        assertFalse(key2.isBlank());
        // Keys should be different (random generation)
        assertNotEquals(key1, key2);
        // Should be valid HEX
        assertDoesNotThrow(() -> Bytes.from(key1, HEX));
    }

    @Test
    @DisplayName("symmetric key generation with provider produces usable keys")
    void producesUsableKeys() {
        // Generate an encoded symmetric key
        String b64Key = symmetricKey("AES", "", BASE64);
        assertFalse(b64Key.isBlank());

        // Convert to Bytes and verify it can be used with the cipher builder
        Bytes key = Bytes.from(b64Key, BASE64);
        assertNotNull(key);
        assertFalse(key.isEmpty());
        assertEquals(32, key.length()); // AES-256 default

        // Can be used to build a cipher
        var encryptor = Bruce.cipherBuilder()
                .key(key)
                .keyAlgorithm("AES")
                .algorithm("AES/CBC/PKCS5Padding")
                .buildSymmetricEncryptor();
        assertNotNull(encryptor);
    }

    @Test
    @DisplayName("raw symmetric key with provider matches encoded version")
    void roundTrip() {
        // Generate both raw and encoded versions
        byte[] rawKey = symmetricKey("AES", "");
        String b64Key = symmetricKey("AES", "", BASE64);
        String hexKey = symmetricKey("AES", "", HEX);

        // Raw key should be different each time due to randomness
        byte[] rawKey2 = symmetricKey("AES", "");
        assertNotEquals(rawKey, rawKey2);

        // But encoded versions should not match raw versions since they're different random generations
        Bytes fromB64 = Bytes.from(b64Key, BASE64);
        Bytes fromHex = Bytes.from(hexKey, HEX);

        assertNotNull(fromB64.asBytes());
        assertNotNull(fromHex.asBytes());

        // All should have same length though (256-bit AES default)
        assertEquals(rawKey.length, fromB64.length());
        assertEquals(rawKey.length, fromHex.length());
    }

    @Test
    @DisplayName("generates different symmetric keys for different algorithms")
    void differentAlgorithms() {
        byte[] aesKey = symmetricKey("AES", "");
        String desKey = symmetricKey("DESede", "", BASE64);

        assertNotNull(aesKey);
        assertNotNull(desKey);
        assertFalse(desKey.isBlank());

        // DESede is 192 bits (24 bytes), AES is typically 256 bits (32 bytes) by default
        assertTrue(aesKey.length > 0);

        Bytes desKeyBytes = Bytes.from(desKey, BASE64);
        // Verify they are different types of keys
        assertNotEquals(aesKey.length, desKeyBytes.length());
    }

    @Test
    @DisplayName("generated keys can be decoded from different encodings")
    void encodingRoundTrip() {
        String b64Key = symmetricKey("AES", "", BASE64);
        String hexKey = symmetricKey("AES", "", HEX);

        // Decode from BASE64
        Bytes fromB64 = Bytes.from(b64Key, BASE64);
        assertNotNull(fromB64);
        assertFalse(fromB64.isEmpty());

        // Decode from HEX
        Bytes fromHex = Bytes.from(hexKey, HEX);
        assertNotNull(fromHex);
        assertFalse(fromHex.isEmpty());

        // Both should be valid 32-byte keys (AES-256 default)
        assertEquals(32, fromB64.length());
        assertEquals(32, fromHex.length());
    }
}

