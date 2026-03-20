package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

final class KeyStoreSources {

    private static final List<KeyStoreSource> SOURCES = List.of(
            new ClasspathKeyStoreSource(),
            new HttpsKeyStoreSource(),
            new HttpKeyStoreSource(),
            new FileKeyStoreSource()
    );

    private KeyStoreSources() {
        // utility class
    }

    static InputStream open(String location) throws IOException {
        for (KeyStoreSource source : SOURCES) {
            if (source.supports(location)) {
                return source.open(location);
            }
        }
        throw new IOException("unsupported keystore location: " + location);
    }
}

