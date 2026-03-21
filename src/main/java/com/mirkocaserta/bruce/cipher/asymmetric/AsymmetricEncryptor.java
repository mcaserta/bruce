package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs asymmetric encryption with a key configured by the implementation.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface AsymmetricEncryptor {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] encrypt(byte[] plaintext);

    default byte[] encrypt(String plaintext, Charset charset) {
        return encrypt(plaintext.getBytes(charset));
    }

    default byte[] encrypt(String plaintext) {
        return encrypt(plaintext, charset());
    }

    default String encryptToString(byte[] plaintext, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, encrypt(plaintext));
    }

    default String encryptToString(byte[] plaintext) {
        return encryptToString(plaintext, encoding());
    }

    default String encryptToString(String plaintext, Charset charset, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, encrypt(plaintext, charset));
    }

    default String encryptToString(String plaintext, Charset charset) {
        return encryptToString(plaintext, charset, encoding());
    }

    default String encryptToString(String plaintext, Bruce.Encoding encoding) {
        return encryptToString(plaintext, charset(), encoding);
    }

    default String encryptToString(String plaintext) {
        return encryptToString(plaintext, charset(), encoding());
    }

    /**
     * Encrypts the given {@link Bytes} plaintext and returns the ciphertext as {@link Bytes}.
     *
     * @param plaintext the plaintext to encrypt
     * @return the ciphertext wrapped in {@link Bytes}
     */
    default Bytes encrypt(Bytes plaintext) {
        return Bytes.from(encrypt(plaintext.asBytes()));
    }
}

