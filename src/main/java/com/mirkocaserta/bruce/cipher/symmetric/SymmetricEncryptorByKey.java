package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs symmetric encryption with a runtime-provided key.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface SymmetricEncryptorByKey {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext);

    default byte[] encrypt(byte[] key, byte[] iv, String plaintext, Charset charset) {
        return encrypt(key, iv, plaintext.getBytes(charset));
    }

    default byte[] encrypt(byte[] key, byte[] iv, String plaintext) {
        return encrypt(key, iv, plaintext, charset());
    }

    default byte[] encrypt(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, byte[] plaintext) {
        return encrypt(EncodingUtils.decode(keyEncoding, key), EncodingUtils.decode(ivEncoding, iv), plaintext);
    }

    default byte[] encrypt(String key, String iv, byte[] plaintext) {
        return encrypt(key, encoding(), iv, encoding(), plaintext);
    }

    default String encryptToString(byte[] key, byte[] iv, byte[] plaintext, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(key, iv, plaintext));
    }

    default String encryptToString(byte[] key, byte[] iv, byte[] plaintext) {
        return encryptToString(key, iv, plaintext, encoding());
    }

    default String encryptToString(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, byte[] plaintext, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(key, keyEncoding, iv, ivEncoding, plaintext));
    }

    default String encryptToString(String key, String iv, byte[] plaintext) {
        return encryptToString(key, encoding(), iv, encoding(), plaintext, encoding());
    }

    default String encryptToString(byte[] key, byte[] iv, String plaintext, Charset charset, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(key, iv, plaintext.getBytes(charset)));
    }

    default String encryptToString(byte[] key, byte[] iv, String plaintext) {
        return encryptToString(key, iv, plaintext, charset(), encoding());
    }

    default String encryptToString(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, String plaintext, Charset charset, Bruce.Encoding outputEncoding) {
        return EncodingUtils.encode(outputEncoding, encrypt(key, keyEncoding, iv, ivEncoding, plaintext.getBytes(charset)));
    }

    default String encryptToString(String key, String iv, String plaintext) {
        return encryptToString(key, encoding(), iv, encoding(), plaintext, charset(), encoding());
    }
}

