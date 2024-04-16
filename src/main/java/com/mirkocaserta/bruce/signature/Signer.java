package com.mirkocaserta.bruce.signature;

import com.mirkocaserta.bruce.BruceException;

/**
 * An interface for providing digital signatures.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Signer {

    /**
     * Signs a message.
     *
     * @param message the message to sign
     * @return the signature
     * @throws BruceException on signing errors
     */
    byte[] sign(byte[] message);

    /**
     * Signs a message.
     *
     * @param message the message to sign
     * @return an encoded version of the signature
     */
    String sign(String message);

}
