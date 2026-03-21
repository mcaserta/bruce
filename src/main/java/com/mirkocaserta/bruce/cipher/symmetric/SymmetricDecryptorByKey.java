package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs symmetric decryption with a runtime-provided key.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes plaintext = decryptorByKey.decrypt(keyBytes, ivBytes, ciphertext);
 * String text     = plaintext.asString();
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface SymmetricDecryptorByKey {

    /**
     * Decrypts the given ciphertext using the provided key and initialization vector.
     *
     * @param key        the decryption key
     * @param iv         the initialization vector
     * @param ciphertext the ciphertext to decrypt
     * @return the plaintext wrapped in {@link Bytes}
     */
    Bytes decrypt(Bytes key, Bytes iv, Bytes ciphertext);
}
