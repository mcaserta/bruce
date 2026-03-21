package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * An immutable wrapper around a raw byte array that can be constructed from and
 * converted to various representations (plain text, HEX, BASE64, etc.) on demand.
 *
 * <p>This is the universal currency type for all Bruce cryptographic operations.
 * Raw bytes are the canonical form; every other representation is a view.</p>
 *
 * <pre>{@code
 * // Construction
 * Bytes b = Bytes.from(new byte[]{0, 1, 2});      // raw bytes
 * Bytes b = Bytes.from("Hello");                   // UTF-8 text
 * Bytes b = Bytes.from("Hello", ISO_8859_1);       // explicit charset
 * Bytes b = Bytes.from("cafebabe", Bruce.Encoding.HEX);    // decode hex
 * Bytes b = Bytes.from("c2lnbg==", Bruce.Encoding.BASE64); // decode base64
 * Bytes b = Bytes.fromFile(Path.of("secret.bin")); // file contents
 *
 * // Consumption
 * byte[] raw     = b.asBytes();
 * String base64  = b.encode(Bruce.Encoding.BASE64);
 * String hex     = b.encode(Bruce.Encoding.HEX);
 * String text    = b.asString();           // UTF-8
 * String latin1  = b.asString(ISO_8859_1);
 * int    len     = b.length();
 * boolean empty  = b.isEmpty();
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bytes {

    private final byte[] bytes;

    private Bytes(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }

    // ── Factories ────────────────────────────────────────────────────────────

    /**
     * Creates a {@code Bytes} instance wrapping the given raw byte array.
     * A defensive copy is made.
     *
     * @param bytes the raw bytes; must not be {@code null}
     * @return a new {@code Bytes} instance
     * @throws NullPointerException if {@code bytes} is {@code null}
     */
    public static Bytes from(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes must not be null");
        return new Bytes(bytes);
    }

    /**
     * Creates a {@code Bytes} instance from a UTF-8 encoded string.
     *
     * @param text the input text; must not be {@code null}
     * @return a new {@code Bytes} instance
     * @throws NullPointerException if {@code text} is {@code null}
     */
    public static Bytes from(String text) {
        return from(text, UTF_8);
    }

    /**
     * Creates a {@code Bytes} instance from a string using the given charset.
     *
     * @param text    the input text; must not be {@code null}
     * @param charset the charset to use for encoding; must not be {@code null}
     * @return a new {@code Bytes} instance
     * @throws NullPointerException if {@code text} or {@code charset} is {@code null}
     */
    public static Bytes from(String text, Charset charset) {
        Objects.requireNonNull(text, "text must not be null");
        Objects.requireNonNull(charset, "charset must not be null");
        return new Bytes(text.getBytes(charset));
    }

    /**
     * Creates a {@code Bytes} instance by decoding an encoded string.
     *
     * @param encoded  the encoded input string; must not be {@code null}
     * @param encoding the encoding format (HEX, BASE64, URL, MIME); must not be {@code null}
     * @return a new {@code Bytes} instance
     * @throws NullPointerException if {@code encoded} or {@code encoding} is {@code null}
     * @throws BruceException       if the string is not valid for the given encoding
     */
    public static Bytes from(String encoded, Bruce.Encoding encoding) {
        Objects.requireNonNull(encoded, "encoded must not be null");
        Objects.requireNonNull(encoding, "encoding must not be null");
        return new Bytes(EncodingUtils.decode(encoding, encoded));
    }

    /**
     * Creates a {@code Bytes} instance from the full contents of a file.
     *
     * @param path the file path; must not be {@code null}
     * @return a new {@code Bytes} instance
     * @throws NullPointerException if {@code path} is {@code null}
     * @throws BruceException       if the file cannot be read
     */
    public static Bytes fromFile(Path path) {
        Objects.requireNonNull(path, "path must not be null");
        try {
            return new Bytes(Files.readAllBytes(path));
        } catch (IOException e) {
            throw new BruceException("error reading file: " + path, e);
        }
    }

    /**
     * Creates a {@code Bytes} instance from the full contents of a file.
     *
     * @param file the file; must not be {@code null}
     * @return a new {@code Bytes} instance
     * @throws NullPointerException if {@code file} is {@code null}
     * @throws BruceException       if the file cannot be read
     */
    public static Bytes fromFile(File file) {
        Objects.requireNonNull(file, "file must not be null");
        return fromFile(file.toPath());
    }

    // ── Views ────────────────────────────────────────────────────────────────

    /**
     * Returns a copy of the underlying raw byte array.
     *
     * @return a defensive copy of the raw bytes
     */
    public byte[] asBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    /**
     * Encodes the raw bytes using the given encoding.
     *
     * @param encoding the encoding format (HEX, BASE64, URL, MIME); must not be {@code null}
     * @return the encoded string representation
     */
    public String encode(Bruce.Encoding encoding) {
        Objects.requireNonNull(encoding, "encoding must not be null");
        return EncodingUtils.encode(encoding, bytes);
    }

    /**
     * Decodes the raw bytes as a UTF-8 string.
     *
     * @return the string value interpreted as UTF-8
     */
    public String asString() {
        return asString(UTF_8);
    }

    /**
     * Decodes the raw bytes as a string using the given charset.
     *
     * @param charset the charset to use; must not be {@code null}
     * @return the string value
     */
    public String asString(Charset charset) {
        Objects.requireNonNull(charset, "charset must not be null");
        return new String(bytes, charset);
    }

    /**
     * Returns {@code true} if this instance holds zero bytes.
     *
     * @return {@code true} if empty
     */
    public boolean isEmpty() {
        return bytes.length == 0;
    }

    /**
     * Returns the number of bytes held by this instance.
     *
     * @return byte count
     */
    public int length() {
        return bytes.length;
    }

    // ── Object contract ──────────────────────────────────────────────────────

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Bytes other)) return false;
        return Arrays.equals(bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    /** Returns a safe summary string that does not expose the byte contents. */
    @Override
    public String toString() {
        return "Bytes[" + bytes.length + "]";
    }
}

