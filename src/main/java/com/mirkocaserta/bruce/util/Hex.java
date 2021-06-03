package com.mirkocaserta.bruce.util;

import com.mirkocaserta.bruce.BruceException;

import java.nio.charset.StandardCharsets;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Hexadecimal utilities for encoding/decoding bytes and strings.
 */
public class Hex {

    private static final byte[] HEX_ARRAY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    private static final Encoder ENCODER = new Encoder();

    private static final Decoder DECODER = new Decoder();

    private Hex() {
        // utility class, users cannot make new instances
    }

    /**
     * Returns a hexadecimal encoder.
     *
     * @return a hexadecimal encoder
     */
    public static Encoder getEncoder() {
        return ENCODER;
    }

    /**
     * Returns a hexadecimal decoder.
     *
     * @return a hexadecimal decoder
     */
    public static Decoder getDecoder() {
        return DECODER;
    }

    /**
     * A hexadecimal encoder.
     */
    public static final class Encoder {
        /**
         * Encodes the input using hexadecimal characters.
         *
         * @param bytes the bytes to encode
         * @return the hexadecimal encoded bytes
         */
        public String encodeToString(final byte[] bytes) {
            var hexChars = new byte[bytes.length * 2];
            for (var j = 0; j < bytes.length; j++) {
                var v = bytes[j] & 0xFF;
                hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            }
            return new String(hexChars, UTF_8);
        }
    }

    /**
     * A hexadecimal decoder.
     */
    public static final class Decoder {
        /**
         * Decodes the input using hexadecimal characters.
         *
         * @param hex the hexadecimal string to decode
         * @return the decoded bytes
         */
        public byte[] decode(String hex) {
            if (!hex.matches("^[0-9a-fA-F]+$")) {
                throw new BruceException(String.format("input is not a valid hexadecimal string: %s", hex));
            }
            var l = hex.length();
            var data = new byte[l / 2];
            for (var i = 0; i < l; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
            return data;
        }
    }

}
