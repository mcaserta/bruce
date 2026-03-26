package com.mirkocaserta.bruce;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.conscrypt.Conscrypt;

import java.security.Security;
import java.util.stream.Stream;

final class ProviderTestSupport {

    private ProviderTestSupport() {
        // utility class
    }

    static void installProviders() {
        if (Security.getProvider(Bruce.Provider.BOUNCY_CASTLE.providerName()) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(Bruce.Provider.CONSCRYPT.providerName()) == null) {
            try {
                Security.addProvider(Conscrypt.newProvider());
            } catch (UnsatisfiedLinkError | NoClassDefFoundError e) {
                // Conscrypt native library not available for this platform
            }
        }
    }

    static Stream<Bruce.Provider> providers() {
        installProviders();
        var providers = Stream.of(Bruce.Provider.JCA, Bruce.Provider.BOUNCY_CASTLE);
        if (Security.getProvider(Bruce.Provider.CONSCRYPT.providerName()) != null) {
            providers = Stream.concat(providers, Stream.of(Bruce.Provider.CONSCRYPT));
        }
        return providers;
    }
}

