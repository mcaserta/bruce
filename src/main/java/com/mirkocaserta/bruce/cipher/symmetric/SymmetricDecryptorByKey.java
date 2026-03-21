package com.mirkocaserta.bruce.cipher.symmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs symmetric decryption with a runtime-provided key.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface SymmetricDecryptorByKey {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext);

    default byte[] decrypt(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, byte[] ciphertext) {
        return decrypt(EncodingUtils.decode(keyEncoding, key), EncodingUtils.decode(ivEncoding, iv), ciphertext);
    }

    default byte[] decrypt(String key, String iv, byte[] ciphertext) {
        return decrypt(key, encoding(), iv, encoding(), ciphertext);
    }

    default byte[] decrypt(byte[] key, byte[] iv, String ciphertext, Bruce.Encoding ciphertextEncoding) {
        return decrypt(key, iv, EncodingUtils.decode(ciphertextEncoding, ciphertext));
    }

    default byte[] decrypt(byte[] key, byte[] iv, String ciphertext) {
        return decrypt(key, iv, ciphertext, encoding());
    }

    default byte[] decrypt(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, String ciphertext, Bruce.Encoding ciphertextEncoding) {
        return decrypt(
                EncodingUtils.decode(keyEncoding, key),
                EncodingUtils.decode(ivEncoding, iv),
                EncodingUtils.decode(ciphertextEncoding, ciphertext)
        );
    }

    default byte[] decrypt(String key, String iv, String ciphertext) {
        return decrypt(key, encoding(), iv, encoding(), ciphertext, encoding());
    }

    default String decryptToString(byte[] key, byte[] iv, byte[] ciphertext, Charset charset) {
        return new String(decrypt(key, iv, ciphertext), charset);
    }

    default String decryptToString(byte[] key, byte[] iv, byte[] ciphertext) {
        return decryptToString(key, iv, ciphertext, charset());
    }

    default String decryptToString(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, byte[] ciphertext, Charset charset) {
        return new String(decrypt(key, keyEncoding, iv, ivEncoding, ciphertext), charset);
    }

    default String decryptToString(String key, String iv, byte[] ciphertext) {
        return decryptToString(key, encoding(), iv, encoding(), ciphertext, charset());
    }

    default String decryptToString(byte[] key, byte[] iv, String ciphertext, Bruce.Encoding ciphertextEncoding, Charset charset) {
        return new String(decrypt(key, iv, ciphertext, ciphertextEncoding), charset);
    }

    default String decryptToString(byte[] key, byte[] iv, String ciphertext) {
        return decryptToString(key, iv, ciphertext, encoding(), charset());
    }

    default String decryptToString(String key, Bruce.Encoding keyEncoding, String iv, Bruce.Encoding ivEncoding, String ciphertext, Bruce.Encoding ciphertextEncoding, Charset charset) {
        return new String(decrypt(key, keyEncoding, iv, ivEncoding, ciphertext, ciphertextEncoding), charset);
    }

    default String decryptToString(String key, String iv, String ciphertext) {
        return decryptToString(key, encoding(), iv, encoding(), ciphertext, encoding(), charset());
    }

    /**
     * Decrypts the given {@link Bytes} ciphertext using the given {@link Bytes} key and IV
     * and returns the plaintext as {@link Bytes}.
     *
     * @param key        the decryption key
     * @param iv         the initialization vector
     * @param ciphertext the ciphertext to decrypt
     * @return the plaintext wrapped in {@link Bytes}
     */
    default Bytes decrypt(Bytes key, Bytes iv, Bytes ciphertext) {
        return Bytes.from(decrypt(key.asBytes(), iv.asBytes(), ciphertext.asBytes()));
    }
}

