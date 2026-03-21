package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.Bytes;

/**
 * Unified contract for producing digital signatures where the signing key is selected at runtime.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes signature = signerByKey.sign("alice", Bytes.from("Hello Bob"));
 * String hex = signature.encode(Bruce.Encoding.HEX);
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface SignerByKey {

    /**
     * Signs the given message using the key identified by {@code privateKeyId}.
     *
     * @param privateKeyId the key identifier
     * @param message      the message to sign
     * @return the raw signature wrapped in {@link Bytes}
     */
    Bytes sign(String privateKeyId, Bytes message);
}
