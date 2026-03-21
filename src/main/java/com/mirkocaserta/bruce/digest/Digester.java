package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.Bytes;

import java.io.File;
import java.nio.file.Path;

/**
 * Unified digest contract supporting raw bytes and file inputs.
 *
 * <p>Usage examples:</p>
 * <pre>{@code
 * Bytes hash = digester.digest(Bytes.from("hello"));
 * String hex = hash.encode(Bruce.Encoding.HEX);
 *
 * // File hashing (streaming — no full file load)
 * Bytes fileHash = digester.digest(Path.of("data.bin"));
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Digester {

    /**
     * Digests the given input bytes.
     *
     * @param input the bytes to digest
     * @return the digest wrapped in {@link Bytes}
     */
    Bytes digest(Bytes input);

    /**
     * Digests the contents of a file using a streaming read (no full file load into memory).
     *
     * @param file the file path
     * @return the digest wrapped in {@link Bytes}
     */
    Bytes digest(Path file);

    /**
     * Digests the contents of a file.
     *
     * @param file the file
     * @return the digest wrapped in {@link Bytes}
     */
    default Bytes digest(File file) {
        return digest(file.toPath());
    }
}
