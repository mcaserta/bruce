package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs asymmetric encryption with a key configured by the implementation.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes ciphertext = encryptor.encrypt(Bytes.from("secret"));
 * String base64    = ciphertext.encode(Bruce.Encoding.BASE64);
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface AsymmetricEncryptor {

    /**
     * Encrypts the given plaintext.
     *
     * @param plaintext the plaintext to encrypt
     * @return the ciphertext wrapped in {@link Bytes}
     */
    Bytes encrypt(Bytes plaintext);
}
