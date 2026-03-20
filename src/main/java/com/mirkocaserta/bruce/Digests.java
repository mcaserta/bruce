package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for digest operations.
 */
public final class Digests {

    private Digests() {
        // utility class
    }

    public static DigestBuilder builder() {
        return new DigestBuilder();
    }
}
