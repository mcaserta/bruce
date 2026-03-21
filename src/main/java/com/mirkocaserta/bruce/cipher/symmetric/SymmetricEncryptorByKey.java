package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs symmetric encryption with a runtime-provided key.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes ciphertext = encryptorByKey.encrypt(keyBytes, ivBytes, Bytes.from("secret"));
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface SymmetricEncryptorByKey {

    /**
     * Encrypts the given plaintext using the provided key and initialization vector.
     *
     * @param key       the encryption key
     * @param iv        the initialization vector
     * @param plaintext the plaintext to encrypt
     * @return the ciphertext wrapped in {@link Bytes}
     */
    Bytes encrypt(Bytes key, Bytes iv, Bytes plaintext);
}
