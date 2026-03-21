package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs asymmetric encryption with a key selected at runtime.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface AsymmetricEncryptorByKey {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] encrypt(String keyId, byte[] plaintext);

    default byte[] encrypt(String keyId, String plaintext, Charset charset) {
        return encrypt(keyId, plaintext.getBytes(charset));
    }

    default byte[] encrypt(String keyId, String plaintext) {
        return encrypt(keyId, plaintext, charset());
    }

    default String encryptToString(String keyId, byte[] plaintext, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, encrypt(keyId, plaintext));
    }

    default String encryptToString(String keyId, byte[] plaintext) {
        return encryptToString(keyId, plaintext, encoding());
    }

    default String encryptToString(String keyId, String plaintext, Charset charset, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, encrypt(keyId, plaintext, charset));
    }

    default String encryptToString(String keyId, String plaintext, Charset charset) {
        return encryptToString(keyId, plaintext, charset, encoding());
    }

    default String encryptToString(String keyId, String plaintext, Bruce.Encoding encoding) {
        return encryptToString(keyId, plaintext, charset(), encoding);
    }

    default String encryptToString(String keyId, String plaintext) {
        return encryptToString(keyId, plaintext, charset(), encoding());
    }

    /**
     * Encrypts the given {@link Bytes} plaintext using the key identified by {@code keyId}
     * and returns the ciphertext as {@link Bytes}.
     *
     * @param keyId     the key identifier
     * @param plaintext the plaintext to encrypt
     * @return the ciphertext wrapped in {@link Bytes}
     */
    default Bytes encrypt(String keyId, Bytes plaintext) {
        return Bytes.from(encrypt(keyId, plaintext.asBytes()));
    }
}

