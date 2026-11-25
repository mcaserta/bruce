package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;

import java.util.Base64;

/**
 * Utility methods for PEM encoding and decoding.
 *
 * <p>PEM (Privacy-Enhanced Mail) is a Base64-encoded format wrapped in
 * {@code -----BEGIN <type>-----} / {@code -----END <type>-----} header and footer lines.</p>
 *
 * @author Mirko Caserta (info@mirkocaserta.com)
 */
public final class PemUtils {

    private static final String LINE_SEPARATOR = System.lineSeparator();
    private static final String DASHES = "-----";
    private static final String BEGIN = DASHES + "BEGIN ";
    private static final String END = DASHES + "END ";

    private PemUtils() {
        // utility class
    }

    /**
     * Decodes a PEM-encoded string to raw bytes.
     *
     * <p>The first {@code -----BEGIN <label>-----} / {@code -----END <label>-----}
     * block is decoded. Text before it (for example OpenSSL "Bag Attributes") and
     * anything after its END line are ignored. The END label must match the BEGIN
     * label, and RFC 1421 encapsulated headers such as {@code Proc-Type} and
     * {@code DEK-Info} (legacy encrypted keys) are rejected.</p>
     *
     * @param pem the PEM string; must not be {@code null} or blank
     * @return the raw DER bytes
     * @throws BruceException if the input is not valid PEM
     */
    public static byte[] decode(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new BruceException("pem must not be null or blank");
        }
        String label = null;
        var body = new StringBuilder();
        for (var it = pem.lines().iterator(); it.hasNext(); ) {
            var line = it.next().strip();
            if (label == null) {
                if (line.startsWith(BEGIN) && line.endsWith(DASHES)) {
                    label = line.substring(BEGIN.length(), line.length() - DASHES.length());
                }
                continue;
            }
            if (line.startsWith(END)) {
                if (!line.equals(END + label + DASHES)) {
                    throw new BruceException("PEM END line does not match BEGIN " + label);
                }
                return decodeBody(body);
            }
            if (line.indexOf(':') >= 0) {
                throw new BruceException("PEM headers are not supported (encrypted legacy keys must be decrypted first)");
            }
            body.append(line);
        }
        if (label == null) {
            throw new BruceException("no PEM BEGIN line found");
        }
        throw new BruceException("PEM END line missing for BEGIN " + label);
    }

    private static byte[] decodeBody(CharSequence body) {
        if (body.isEmpty()) {
            throw new BruceException("PEM block is empty");
        }
        try {
            return Base64.getDecoder().decode(body.toString());
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

