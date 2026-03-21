package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs asymmetric decryption with a key configured by the implementation.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface AsymmetricDecryptor {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] decrypt(byte[] ciphertext);

    default byte[] decrypt(String ciphertext, Bruce.Encoding encoding) {
        return decrypt(EncodingUtils.decode(encoding, ciphertext));
    }

    default byte[] decrypt(String ciphertext) {
        return decrypt(ciphertext, encoding());
    }

    default String decryptToString(byte[] ciphertext, Charset charset) {
        return new String(decrypt(ciphertext), charset);
    }

    default String decryptToString(byte[] ciphertext) {
        return decryptToString(ciphertext, charset());
    }

    default String decryptToString(String ciphertext, Bruce.Encoding encoding, Charset charset) {
        return new String(decrypt(ciphertext, encoding), charset);
    }

    default String decryptToString(String ciphertext, Bruce.Encoding encoding) {
        return decryptToString(ciphertext, encoding, charset());
    }

    default String decryptToString(String ciphertext, Charset charset) {
        return decryptToString(ciphertext, encoding(), charset);
    }

    default String decryptToString(String ciphertext) {
        return decryptToString(ciphertext, encoding(), charset());
    }
}

