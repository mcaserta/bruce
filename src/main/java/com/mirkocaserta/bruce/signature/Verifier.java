package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bytes;


/**
 * Unified contract for verifying digital signatures.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * boolean ok = verifier.verify(
 *     Bytes.from("Hello Bob"),
 *     Bytes.from(base64Signature, Bruce.Encoding.BASE64));
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface Verifier {

    /**
     * Verifies the signature against the message.
     *
     * @param message   the original message
     * @param signature the signature to verify
     * @return {@code true} if the signature is valid
     */
    boolean verify(Bytes message, Bytes signature);

}
