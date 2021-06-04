package com.mirkocaserta.bruce.signature;

/**
 * An interface for verifying the authenticity of messages using
 * encoded digital signatures where the public key
 * is configured in an underlying map using a logical name.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingVerifierByKey {

    /**
     * Verifies the authenticity of a message using an encoded digital signature.
     *
     * @param publicKeyId the logical name of the public key as configured
     *                    in the underlying map
     * @param message     the original message to verify
     * @param signature   the encoded digital signature
     * @return true if the original message is verified by the digital signature
     */
    boolean verify(String publicKeyId, String message, String signature);

}
