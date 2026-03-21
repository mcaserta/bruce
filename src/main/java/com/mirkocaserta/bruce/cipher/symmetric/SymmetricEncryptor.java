package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs symmetric encryption with a configured key.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface SymmetricEncryptor {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] encrypt(byte[] iv, byte[] plaintext);

    default byte[] encrypt(byte[] iv, String plaintext, Charset charset) {
        return encrypt(iv, plaintext.getBytes(charset));
    }

    default byte[] encrypt(byte[] iv, String plaintext) {
        return encrypt(iv, plaintext, charset());
    }

    default byte[] encrypt(String iv, Bruce.Encoding ivEncoding, byte[] plaintext) {
        return encrypt(EncodingUtils.decode(ivEncoding, iv), plaintext);
    }

    default byte[] encrypt(String iv, byte[] plaintext) {
        return encrypt(iv, encoding(), plaintext);
    }

    default String encryptToString(byte[] iv, byte[] plaintext, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(iv, plaintext));
    }

    default String encryptToString(byte[] iv, byte[] plaintext) {
        return encryptToString(iv, plaintext, encoding());
    }

    default String encryptToString(byte[] iv, String plaintext, Charset charset, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(iv, plaintext, charset));
    }

    default String encryptToString(byte[] iv, String plaintext) {
        return encryptToString(iv, plaintext, charset(), encoding());
    }

    default String encryptToString(String iv, Bruce.Encoding ivEncoding, byte[] plaintext, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(iv, ivEncoding, plaintext));
    }

    default String encryptToString(String iv, byte[] plaintext) {
        return encryptToString(iv, encoding(), plaintext, encoding());
    }

    default String encryptToString(String iv, Bruce.Encoding ivEncoding, String plaintext, Charset charset, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(iv, ivEncoding, plaintext.getBytes(charset)));
    }

    default String encryptToString(String iv, String plaintext) {
        return encryptToString(iv, encoding(), plaintext, charset(), encoding());
    }
}

