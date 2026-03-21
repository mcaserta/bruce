package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs symmetric encryption with a configured key.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes iv         = Bytes.from(ivBytes);
 * Bytes ciphertext = encryptor.encrypt(iv, Bytes.from("secret message"));
 * String base64    = ciphertext.encode(Bruce.Encoding.BASE64);
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface SymmetricEncryptor {

    /**
     * Encrypts the given plaintext using the given initialization vector.
     *
     * @param iv        the initialization vector
     * @param plaintext the plaintext to encrypt
     * @return the ciphertext wrapped in {@link Bytes}
     */
    Bytes encrypt(Bytes iv, Bytes plaintext);
}
