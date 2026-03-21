package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.util.Preconditions;
import org.junit.jupiter.api.Test;

import static com.mirkocaserta.bruce.Keystores.keyPair;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for argument validation in builders and utilities.
 * Verifies that the APIs properly validate input parameters and throw appropriate exceptions.
 */
class ArgumentValidationTest {

    @Test
    void preconditionsRequireNonNull() {
        var ex = assertThrows(BruceException.class, () -> Preconditions.requireNonNull(null, "myField"));
        assertEquals("myField must not be null", ex.getMessage());
    }

    @Test
    void preconditionsRequireNonBlank() {
        assertThrows(BruceException.class, () -> Preconditions.requireNonBlank(null, "myField"));
        assertThrows(BruceException.class, () -> Preconditions.requireNonBlank("  ", "myField"));
        assertDoesNotThrow(() -> Preconditions.requireNonBlank("value", "myField"));
    }

    @Test
    void preconditionsRequireNonEmptyMap() {
        java.util.Map<?, ?> nullMap = null;
        assertThrows(BruceException.class, () -> Preconditions.requireNonEmpty(nullMap, "myMap"));
        assertThrows(BruceException.class, () -> Preconditions.requireNonEmpty(java.util.Map.of(), "myMap"));
        assertDoesNotThrow(() -> Preconditions.requireNonEmpty(java.util.Map.of("k", "v"), "myMap"));
    }

    @Test
    void signerBuilderRejectsNullKey() {
        var ex = assertThrows(BruceException.class, () ->
                Bruce.signerBuilder().algorithm("SHA256withRSA").build());
        assertTrue(ex.getMessage().contains("privateKey"));
    }

    @Test
    void signerBuilderRejectsBlankAlgorithm() {
        var kp = keyPair("RSA", 2048);
        assertThrows(BruceException.class, () ->
                Bruce.signerBuilder().key(kp.getPrivate()).build());
    }

    @Test
    void verifierBuilderRejectsNullKey() {
        var ex = assertThrows(BruceException.class, () ->
                Bruce.verifierBuilder().algorithm("SHA256withRSA").build());
        assertTrue(ex.getMessage().contains("publicKey"));
    }

    @Test
    void digestBuilderRejectsBlankAlgorithm() {
        assertThrows(BruceException.class, () -> Bruce.digestBuilder().build());
    }

    @Test
    void macBuilderRejectsNullKey() {
        assertThrows(BruceException.class, () ->
                Bruce.macBuilder().algorithm("HmacSHA256").build());
    }
}

