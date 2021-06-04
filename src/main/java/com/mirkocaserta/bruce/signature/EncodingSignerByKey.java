package com.mirkocaserta.bruce.signature;

/**
 * An interface for providing encoded digital signatures where the private key
 * is configured in an underlying map using a logical name.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingSignerByKey {

    /**
     * Signs a message.
     *
     * @param privateKeyId the logical name of the private key as configured
     *                     in the underlying map
     * @param message      the message to sign
     * @return an encoded version of the signature
     */
    String sign(String privateKeyId, String message);

}
