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
            Security.addProvider(Conscrypt.newProvider());
        }
    }

    static Stream<Bruce.Provider> providers() {
        installProviders();
        return Stream.of(Bruce.Provider.JCA, Bruce.Provider.BOUNCY_CASTLE, Bruce.Provider.CONSCRYPT);
    }
}

