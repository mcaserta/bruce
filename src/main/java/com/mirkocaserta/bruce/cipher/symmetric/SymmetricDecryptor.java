package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs symmetric decryption with a configured key.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes plaintext = decryptor.decrypt(iv, ciphertext);
 * String text     = plaintext.asString();
 * }</pre>
 *
 * @author Mirko Caserta (info@mirkocaserta.com)
 */
@FunctionalInterface
public interface SymmetricDecryptor {

    /**
     * Decrypts the given ciphertext using the given initialization vector.
     *
     * @param iv         the initialization vector used for encryption (ignored for ECB)
     * @param ciphertext the ciphertext to decrypt
     * @return the plaintext wrapped in {@link Bytes}
     */
    Bytes decrypt(Bytes iv, Bytes ciphertext);
}
