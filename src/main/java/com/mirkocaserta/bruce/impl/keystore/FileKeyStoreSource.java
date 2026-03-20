package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

final class FileKeyStoreSource implements KeyStoreSource {

    @Override
    public boolean supports(String location) {
        return location != null;
    }

    @Override
    public InputStream open(String location) throws IOException {
        String path = location.replaceFirst("^file:", "");
        return Files.newInputStream(Path.of(path));
    }
}

