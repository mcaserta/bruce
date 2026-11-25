package com.mirkocaserta.bruce.impl.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

final class FileKeyStoreSource implements KeyStoreSource {

    /**
     * Supports plain filesystem paths (including Windows paths), the
     * {@code file:} prefix and {@code file://} URIs. Anything else written as
     * {@code scheme://} is not a file and is left to the resolver to reject.
     */
    @Override
    public boolean supports(String location) {
        if (location == null) {
            return false;
        }
        String scheme = KeyStoreSources.scheme(location);
        return scheme == null || "file".equals(scheme);
    }

    @Override
    public InputStream open(String location) throws IOException {
        String path = location.replaceFirst("^(?i)file:", "");
        Path resolved;
        try {
            resolved = Path.of(path);
        } catch (InvalidPathException e) {
            // the JDK message echoes the raw path, so it is not kept as the cause
            throw new IOException("invalid keystore file path: " + KeyStoreSources.redact(location));
        }
        return Files.newInputStream(resolved);
    }
}
