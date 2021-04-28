package com.mirkocaserta.bruce.cipher.asymmetric;

/**
 * An interface for performing asymmetric encryption/decryption with encoded
 * input/output and a key which is configured in the underlying implementation.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingCipher {

    /**
     * Encrypts/decrypts a message based on the underlying mode of operation.
     *
     * @param message if in encryption mode, the clear-text message, otherwise
     *                the encoded message to decrypt
     * @return if in encryption mode, the encoded encrypted message,
     * otherwise the decrypted message
     */
    String encrypt(String message);

}
