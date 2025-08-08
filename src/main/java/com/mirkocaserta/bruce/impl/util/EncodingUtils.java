package com.mirkocaserta.bruce.impl.util;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.util.Hex;

import java.util.Base64;

/**
 * Implementation class for encoding/decoding operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class EncodingUtils {
    
    private static final Hex.Encoder HEX_ENCODER = Hex.getEncoder();
    private static final Base64.Encoder BASE_64_ENCODER = Base64.getEncoder();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder();
    private static final Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder();
    private static final Hex.Decoder HEX_DECODER = Hex.getDecoder();
    private static final Base64.Decoder BASE_64_DECODER = Base64.getDecoder();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
    private static final Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();
    
    private EncodingUtils() {
        // utility class
    }
    
    /**
     * Decodes the input string using the provided encoding.
     *
     * @param encoding the encoding type
     * @param input the encoded input
     * @return decoded bytes
     * @throws BruceException if the input is invalid for the given encoding
     */
    public static byte[] decode(final Bruce.Encoding encoding, final String input) {
        try {
            if (encoding == Bruce.Encoding.HEX) {
                return HEX_DECODER.decode(input);
            } else if (encoding == Bruce.Encoding.BASE64) {
                return BASE_64_DECODER.decode(input);
            } else if (encoding == Bruce.Encoding.URL) {
                return URL_DECODER.decode(input);
            } else if (encoding == Bruce.Encoding.MIME) {
                return MIME_DECODER.decode(input);
            }
            throw new BruceException("invalid encoding");
        } catch (IllegalArgumentException e) {
            throw new BruceException(String.format("invalid input for encoding %s", encoding));
        }
    }

    /**
     * Encodes the input bytes using the provided encoding.
     *
     * @param encoding the encoding type
     * @param input the raw bytes
     * @return encoded string
     */
    public static String encode(final Bruce.Encoding encoding, final byte[] input) {
        if (encoding == Bruce.Encoding.HEX) {
            return HEX_ENCODER.encodeToString(input);
        } else if (encoding == Bruce.Encoding.BASE64) {
            return BASE_64_ENCODER.encodeToString(input);
        } else if (encoding == Bruce.Encoding.URL) {
            return URL_ENCODER.encodeToString(input);
        } else if (encoding == Bruce.Encoding.MIME) {
            return MIME_ENCODER.encodeToString(input);
        }
        throw new BruceException("invalid encoding");
    }
}