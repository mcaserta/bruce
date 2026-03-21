package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for symmetric and asymmetric cipher operations.
 */
public final class Ciphers {

    private Ciphers() {
        // utility class
    }

    /**
     * Creates a cipher builder.
     *
     * @return a new {@link CipherBuilder}
     */
    public static CipherBuilder builder() {
        return new CipherBuilder();
    }
}
