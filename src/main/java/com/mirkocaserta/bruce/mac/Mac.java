package com.mirkocaserta.bruce.mac;

import com.mirkocaserta.bruce.Bytes;

/**
 * Unified contract for producing Message Authentication Codes.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes mac = mac.get(Bytes.from("message"));
 * String base64 = mac.encode(Bruce.Encoding.BASE64);
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface Mac {

    /**
     * Computes the MAC for the given input message.
     *
     * @param message the input message
     * @return the MAC wrapped in {@link Bytes}
     */
    Bytes get(Bytes message);
}
