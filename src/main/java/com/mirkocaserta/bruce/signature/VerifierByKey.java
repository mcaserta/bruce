package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bytes;

/**
 * Unified contract for verifying digital signatures where the verification key is selected at runtime.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * boolean ok = verifierByKey.verify(
 *     "alice",
 *     Bytes.from("Hello Bob"),
 *     Bytes.from(base64Signature, Bruce.Encoding.BASE64));
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface VerifierByKey {

    /**
     * Verifies the signature against the message using the key identified by {@code publicKeyId}.
     *
     * @param publicKeyId the key identifier
     * @param message     the original message
     * @param signature   the signature to verify
     * @return {@code true} if the signature is valid
     */
    boolean verify(String publicKeyId, Bytes message, Bytes signature);
}
