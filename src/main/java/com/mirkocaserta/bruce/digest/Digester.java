package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Path;

/**
 * Unified digest contract supporting both raw bytes and encoded strings.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Digester {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] digest(byte[] message);

    default byte[] digest(String message, Charset charset) {
        return digest(message.getBytes(charset));
    }

    default byte[] digest(String message) {
        return digest(message, charset());
    }

    default String digestToString(byte[] message, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, digest(message));
    }

    default String digestToString(byte[] message) {
        return digestToString(message, encoding());
    }

    default String digestToString(String message, Charset charset, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, digest(message, charset));
    }

    default String digestToString(String message, Charset charset) {
        return digestToString(message, charset, encoding());
    }

    default String digestToString(String message, Bruce.Encoding encoding) {
        return digestToString(message, charset(), encoding);
    }

    default String digestToString(String message) {
        return digestToString(message, charset(), encoding());
    }

    byte[] digest(Path file);

    default byte[] digest(File file) {
        return digest(file.toPath());
    }

    default String digestToString(Path file, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, digest(file));
    }

    default String digestToString(Path file) {
        return digestToString(file, encoding());
    }

    default String digestToString(File file, Bruce.Encoding encoding) {
        return digestToString(file.toPath(), encoding);
    }

    default String digestToString(File file) {
        return digestToString(file.toPath(), encoding());
    }

    /**
     * Digests the given {@link Bytes} input and returns the result as {@link Bytes}.
     *
     * @param input the input to digest
     * @return the digest wrapped in {@link Bytes}
     */
    default Bytes digest(Bytes input) {
        return Bytes.from(digest(input.asBytes()));
    }
}
