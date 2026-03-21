package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs asymmetric decryption with a key selected at runtime.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes plaintext = decryptorByKey.decrypt("alice", ciphertext);
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface AsymmetricDecryptorByKey {

    /**
     * Decrypts the given ciphertext using the key identified by {@code keyId}.
     *
     * @param keyId      the key identifier
     * @param ciphertext the ciphertext to decrypt
     * @return the plaintext wrapped in {@link Bytes}
     */
    Bytes decrypt(String keyId, Bytes ciphertext);
}
