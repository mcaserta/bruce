package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.BruceException;

/**
 * Generic interface for getting message digests
 * in an encoded format such as hexadecimal or base64.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingDigester {

    /**
     * Returns the message digest in encoded format.
     *
     * @param message the message
     * @return the message digest in encoded format
     * @throws BruceException on digesting errors
     */
    String digest(String message);

}
