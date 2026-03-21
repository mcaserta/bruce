package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs symmetric decryption with a configured key.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface SymmetricDecryptor {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] decrypt(byte[] iv, byte[] ciphertext);

    default byte[] decrypt(String iv, Bruce.Encoding ivEncoding, byte[] ciphertext) {
        return decrypt(EncodingUtils.decode(ivEncoding, iv), ciphertext);
    }

    default byte[] decrypt(String iv, byte[] ciphertext) {
        return decrypt(iv, encoding(), ciphertext);
    }

    default byte[] decrypt(byte[] iv, String ciphertext, Bruce.Encoding ciphertextEncoding) {
        return decrypt(iv, EncodingUtils.decode(ciphertextEncoding, ciphertext));
    }

    default byte[] decrypt(byte[] iv, String ciphertext) {
        return decrypt(iv, ciphertext, encoding());
    }

    default byte[] decrypt(String iv, Bruce.Encoding ivEncoding, String ciphertext, Bruce.Encoding ciphertextEncoding) {
        return decrypt(EncodingUtils.decode(ivEncoding, iv), EncodingUtils.decode(ciphertextEncoding, ciphertext));
    }

    default byte[] decrypt(String iv, String ciphertext) {
        return decrypt(iv, encoding(), ciphertext, encoding());
    }

    default String decryptToString(byte[] iv, byte[] ciphertext, Charset charset) {
        return new String(decrypt(iv, ciphertext), charset);
    }

    default String decryptToString(byte[] iv, byte[] ciphertext) {
        return decryptToString(iv, ciphertext, charset());
    }

    default String decryptToString(String iv, Bruce.Encoding ivEncoding, byte[] ciphertext, Charset charset) {
        return new String(decrypt(iv, ivEncoding, ciphertext), charset);
    }

    default String decryptToString(String iv, byte[] ciphertext) {
        return decryptToString(iv, encoding(), ciphertext, charset());
    }

    default String decryptToString(byte[] iv, String ciphertext, Bruce.Encoding ciphertextEncoding, Charset charset) {
        return new String(decrypt(iv, ciphertext, ciphertextEncoding), charset);
    }

    default String decryptToString(byte[] iv, String ciphertext) {
        return decryptToString(iv, ciphertext, encoding(), charset());
    }

    default String decryptToString(String iv, Bruce.Encoding ivEncoding, String ciphertext, Bruce.Encoding ciphertextEncoding, Charset charset) {
        return new String(decrypt(iv, ivEncoding, ciphertext, ciphertextEncoding), charset);
    }

    default String decryptToString(String iv, String ciphertext) {
        return decryptToString(iv, encoding(), ciphertext, encoding(), charset());
    }
}

