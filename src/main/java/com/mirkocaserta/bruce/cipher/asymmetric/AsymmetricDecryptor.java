package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs asymmetric decryption with a key configured by the implementation.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes plaintext = decryptor.decrypt(Bytes.from(base64Ciphertext, Bruce.Encoding.BASE64));
 * String text     = plaintext.asString();
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface AsymmetricDecryptor {

    /**
     * Decrypts the given ciphertext.
     *
     * @param ciphertext the ciphertext to decrypt
     * @return the plaintext wrapped in {@link Bytes}
     */
    Bytes decrypt(Bytes ciphertext);
}
