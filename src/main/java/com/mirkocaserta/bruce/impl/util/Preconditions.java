package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;

import java.util.Map;

/**
 * Lightweight argument-validation helpers that throw {@link BruceException}
 * with a standardized message on failure.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Preconditions {

    private Preconditions() {
        // utility class
    }

    /**
     * Asserts that {@code value} is not {@code null}.
     *
     * @param value     the value to check
     * @param fieldName human-readable field name used in the error message
     * @throws BruceException if {@code value} is {@code null}
     */
    public static void requireNonNull(Object value, String fieldName) {
        if (value == null) {
            throw new BruceException("%s must not be null".formatted(fieldName));
        }
    }

    /**
     * Asserts that {@code value} is not {@code null} and not blank.
     *
     * @param value     the string to check
     * @param fieldName human-readable field name used in the error message
     * @throws BruceException if {@code value} is {@code null} or blank
     */
    public static void requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new BruceException("%s must not be null or blank".formatted(fieldName));
        }
    }

    /**
     * Asserts that {@code map} is not {@code null} and not empty.
     *
     * @param map       the map to check
     * @param fieldName human-readable field name used in the error message
     * @throws BruceException if {@code map} is {@code null} or empty
     */
    public static void requireNonEmpty(Map<?, ?> map, String fieldName) {
        if (map == null || map.isEmpty()) {
            throw new BruceException("%s must not be null or empty".formatted(fieldName));
        }
    }
}
