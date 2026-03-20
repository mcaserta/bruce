package com.mirkocaserta.bruce.impl.keystore;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

final class ClasspathKeyStoreSource implements KeyStoreSource {

    private static final String PREFIX = "classpath:";

    @Override
    public boolean supports(String location) {
        return location != null && location.startsWith(PREFIX);
    }

    @Override
    public InputStream open(String location) throws IOException {
        String resource = location.replaceFirst("^classpath:", "");
        InputStream inputStream = KeyStoreOperations.class.getResourceAsStream(resource);
        if (inputStream == null) {
            throw new FileNotFoundException("classpath resource not found: " + resource);
        }
        return inputStream;
    }
}

