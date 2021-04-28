package com.mirkocaserta.bruce.cipher.symmetric;

/**
 * Interface for performing symmetric encryption with strings
 * containing encoded versions of raw byte arrays.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingCipher {

    /**
     * Encrypts or decrypts a message. The encryption/decryption mode
     * depends on the configuration of the underlying implementation.
     *
     * @param iv      an encoded version of the initialization vector
     * @param message if in encryption mode, the clear-text message to encrypt,
     *                otherwise an encoded version of the message to decrypt
     * @return if in encryption mode, returns an encoded version of the encrypted message,
     * otherwise returns the decrypted clear-text message
     */
    String encrypt(String iv, String message);

}
