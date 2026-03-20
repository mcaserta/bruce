package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

final class HttpKeyStoreSource implements KeyStoreSource {

    @Override
    public boolean supports(String location) {
        return location != null && location.startsWith("http://");
    }

    @Override
    public InputStream open(String location) throws IOException {
        return URI.create(location).toURL().openConnection().getInputStream();
    }
}

