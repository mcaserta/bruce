package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for digest operations.
 */
public final class Digests {

    private Digests() {
        // utility class
    }

    /**
     * Creates a digest builder.
     *
     * @return a new {@link DigestBuilder}
     */
    public static DigestBuilder builder() {
        return new DigestBuilder();
    }
}
