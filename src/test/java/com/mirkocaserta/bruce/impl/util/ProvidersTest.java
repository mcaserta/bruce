package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProvidersTest {

    @Test
    void resolveBlankReturnsNull() {
        assertNull(Providers.resolve(""));
        assertNull(Providers.resolve("   "));
        assertNull(Providers.resolve(null));
    }

    @Test
    void resolveKnownProviderReturnsProvider() {
        String providerName = Security.getProviders()[0].getName();
        var provider = Providers.resolve(providerName);
        assertNotNull(provider);
        assertEquals(providerName, provider.getName());
    }

    @Test
    void resolveUnknownProviderThrows() {
        assertThrows(BruceException.class, () -> Providers.resolve("__NO_SUCH_PROVIDER__"));
    }
}

