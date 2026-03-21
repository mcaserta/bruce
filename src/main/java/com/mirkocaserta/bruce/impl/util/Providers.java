package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;

import java.security.Provider;
import java.security.Security;

/**
 * Utility methods for provider resolution.
 */
public final class Providers {

    private Providers() {
        // utility class
    }

    /**
     * Resolves a provider by name.
     *
     * @param name provider name; if blank, the default provider chain is used
     * @return resolved provider, or {@code null} when no explicit provider is requested
     */
    public static Provider resolve(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        Provider provider = Security.getProvider(name);
        if (provider == null) {
            throw new BruceException(String.format("no such provider: %s", name));
        }
        return provider;
    }
}

