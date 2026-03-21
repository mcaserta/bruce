package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bytes;

/**
 * Performs asymmetric encryption with a key selected at runtime.
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * Bytes ciphertext = encryptorByKey.encrypt("alice", Bytes.from("secret"));
 * }</pre>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
@FunctionalInterface
public interface AsymmetricEncryptorByKey {

    /**
     * Encrypts the given plaintext using the key identified by {@code keyId}.
     *
     * @param keyId     the key identifier
     * @param plaintext the plaintext to encrypt
     * @return the ciphertext wrapped in {@link Bytes}
     */
    Bytes encrypt(String keyId, Bytes plaintext);
}
