package com.mirkocaserta.bruce.cipher.symmetric;

/**
 * An interface for performing symmetric encryption/decryption.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Cipher {

    /**
     * Encrypts/decrypts a message based on the underlying mode of operation.
     *
     * @param iv      the initialization vector
     * @param message if in encryption mode, the clear-text message, otherwise
     *                the message to decrypt
     * @return if in encryption mode, the encrypted message, otherwise the
     * decrypted message
     */
    byte[] encrypt(byte[] iv, byte[] message);

}
