package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;

import java.util.Base64;

/**
 * Utility methods for PEM encoding and decoding.
 *
 * <p>PEM (Privacy-Enhanced Mail) is a Base64-encoded format wrapped in
 * {@code -----BEGIN <type>-----} / {@code -----END <type>-----} header and footer lines.</p>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class PemUtils {

    private static final String LINE_SEPARATOR = System.lineSeparator();

    private PemUtils() {
        // utility class
    }

    /**
     * Decodes a PEM-encoded string to raw bytes.
     * The header and footer lines are stripped; the remaining Base64 content is decoded.
     *
     * @param pem the PEM string; must not be {@code null} or blank
     * @return the raw DER bytes
     * @throws BruceException if the input is not valid PEM
     */
    public static byte[] decode(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new BruceException("pem must not be null or blank");
        }
        var lines = pem.lines()
                .map(String::trim)
                .filter(l -> !l.startsWith("-----"))
                .reduce("", (a, b) -> a + b);
        try {
            return Base64.getMimeDecoder().decode(lines);
        } catch (IllegalArgumentException e) {
            throw new BruceException("invalid PEM encoding", e);
        }
    }

    /**
     * Encodes raw bytes as a PEM string with the given type.
     *
     * @param type  the PEM type; must not be {@code null}
     * @param bytes the raw DER bytes; must not be {@code null} or empty
     * @return the PEM-encoded string
     */
    public static String encode(com.mirkocaserta.bruce.PemType type, byte[] bytes) {
        if (type == null) {
            throw new BruceException("type must not be null");
        }
        if (bytes == null || bytes.length == 0) {
            throw new BruceException("bytes must not be null or empty");
        }
        // MIME encoder wraps at 76 chars, matching PEM convention
        var b64 = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes()).encodeToString(bytes);
        return "-----BEGIN " + type.label() + "-----" + LINE_SEPARATOR
                + b64 + LINE_SEPARATOR
                + "-----END " + type.label() + "-----";
    }

}

