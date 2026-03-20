package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for message authentication code operations.
 */
public final class Macs {

    private Macs() {
        // utility class
    }

    public static MacBuilder builder() {
        return new MacBuilder();
    }
}
