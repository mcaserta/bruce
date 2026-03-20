package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for symmetric and asymmetric cipher operations.
 */
public final class Ciphers {

    private Ciphers() {
        // utility class
    }

    public static CipherBuilder builder() {
        return new CipherBuilder();
    }
}
