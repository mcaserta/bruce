package com.mirkocaserta.bruce.mac;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Unified contract for producing Message Authentication Codes.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
*/
public interface Mac {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] get(byte[] message);

    default byte[] get(String message, Charset charset) {
        return get(message.getBytes(charset));
    }

    default byte[] get(String message) {
        return get(message, charset());
    }

    default String getToString(byte[] message, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, get(message));
    }

    default String getToString(byte[] message) {
        return getToString(message, encoding());
    }

    default String getToString(String message, Charset charset, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, get(message, charset));
    }

    default String getToString(String message, Charset charset) {
        return getToString(message, charset, encoding());
    }

    default String getToString(String message, Bruce.Encoding encoding) {
        return getToString(message, charset(), encoding);
    }

    default String getToString(String message) {
        return getToString(message, charset(), encoding());
    }

    /**
     * Computes the MAC for the given {@link Bytes} input and returns the result as {@link Bytes}.
     *
     * @param message the input message
     * @return the MAC wrapped in {@link Bytes}
     */
    default Bytes get(Bytes message) {
        return Bytes.from(get(message.asBytes()));
    }
}
