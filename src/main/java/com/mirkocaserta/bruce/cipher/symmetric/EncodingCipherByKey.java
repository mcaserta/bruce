package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bruce.Encoding;

/**
 * Interface for performing symmetric encryption with strings
 * containing encoded versions of raw byte arrays.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingCipherByKey {

    /**
     * Encrypts or decrypts a message. The encryption/decryption mode
     * depends on the configuration of the underlying implementation.
     *
     * @param key      an encoded version of the symmetric key
     * @param iv       an encoded version of the initialization vector
     * @param message  if in encryption mode, the clear-text message to encrypt,
     *                 otherwise an encoded version of the message to decrypt
     * @param encoding the encoding to use
     * @return if in encryption mode, returns an encoded version of the encrypted message,
     * otherwise returns the decrypted clear-text message
     */
    String encrypt(String key, String iv, String message, Encoding encoding);

}
