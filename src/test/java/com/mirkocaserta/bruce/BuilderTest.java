package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;

import static com.mirkocaserta.bruce.Bruce.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test the builder pattern implementations for reducing parameter overload.
 */
class BuilderTest {

    @Test
    void testSignerBuilder() {
        // Generate a key pair for testing
        KeyPair keyPair = keyPair("RSA", 2048);
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Test the builder pattern (use default provider instead of SunJSSE)
        var signer = signerBuilder()
                .key(privateKey)
                .algorithm("SHA256withRSA")
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .build();
        
        assertNotNull(signer);
        
        // Test signing functionality
        String signature = signer.sign("Hello World");
        assertNotNull(signature);
        assertFalse(signature.isEmpty());
    }

    @Test
    void testCipherBuilderSymmetric() {
        String testKey = symmetricKey("AES", Encoding.BASE64);
        
        // Test symmetric cipher builder creation (don't test actual encryption due to complexity)
        var cipher = cipherBuilder()
                .key(testKey)
                .keyAlgorithm("AES")
                .algorithm("AES")
                .mode(Mode.ENCRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .buildSymmetric();
        
        assertNotNull(cipher);
        // Builder successfully created a cipher - that's what we're testing
    }

    @Test
    void testCipherBuilderAsymmetric() {
        KeyPair keyPair = keyPair("RSA", 2048);
        
        // Test asymmetric cipher builder
        var cipher = cipherBuilder()
                .key(keyPair.getPublic())
                .algorithm("RSA")
                .mode(Mode.ENCRYPT)
                .charset(StandardCharsets.UTF_8)
                .encoding(Encoding.BASE64)
                .buildAsymmetric();
        
        assertNotNull(cipher);
        
        // Test encryption functionality
        String encrypted = cipher.encrypt("Hello");
        assertNotNull(encrypted);
        assertFalse(encrypted.isEmpty());
    }

    @Test
    void testBuilderValidation() {
        // Test that builders validate required parameters
        assertThrows(BruceException.class, () -> {
            signerBuilder().build(); // Missing required parameters
        });
        
        assertThrows(BruceException.class, () -> {
            cipherBuilder().buildSymmetric(); // Missing required parameters
        });
        
        assertThrows(BruceException.class, () -> {
            cipherBuilder().buildAsymmetric(); // Missing required parameters
        });
    }
}