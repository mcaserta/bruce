package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bytes;

/**
 * Unified contract for producing digital signatures.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes signature = signer.sign(Bytes.from("Hello Bob"));
 * String base64   = signature.encode(Bruce.Encoding.BASE64);
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface Signer {

    /**
     * Signs the given message and returns the raw signature.
     *
     * @param message the message to sign
     * @return the raw signature wrapped in {@link Bytes}
     */
    Bytes sign(Bytes message);
}
