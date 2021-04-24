package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.BruceException;

/**
 * Generic interface for getting message digests
 * in raw bytes format.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Digester {

    /**
     * Returns the message digest in raw bytes format.
     *
     * @param message the message
     * @return the message digest in raw bytes format
     * @throws BruceException on digesting errors
     */
    byte[] digest(byte[] message);

}
