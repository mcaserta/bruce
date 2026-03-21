package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;

/**
 * Performs asymmetric decryption with a key selected at runtime.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface AsymmetricDecryptorByKey {

    Charset charset();

    Bruce.Encoding encoding();

    byte[] decrypt(String keyId, byte[] ciphertext);

    default byte[] decrypt(String keyId, String ciphertext, Bruce.Encoding encoding) {
        return decrypt(keyId, EncodingUtils.decode(encoding, ciphertext));
    }

    default byte[] decrypt(String keyId, String ciphertext) {
        return decrypt(keyId, ciphertext, encoding());
    }

    default String decryptToString(String keyId, byte[] ciphertext, Charset charset) {
        return new String(decrypt(keyId, ciphertext), charset);
    }

    default String decryptToString(String keyId, byte[] ciphertext) {
        return decryptToString(keyId, ciphertext, charset());
    }

    default String decryptToString(String keyId, String ciphertext, Bruce.Encoding encoding, Charset charset) {
        return new String(decrypt(keyId, ciphertext, encoding), charset);
    }

    default String decryptToString(String keyId, String ciphertext, Bruce.Encoding encoding) {
        return decryptToString(keyId, ciphertext, encoding, charset());
    }

    default String decryptToString(String keyId, String ciphertext, Charset charset) {
        return decryptToString(keyId, ciphertext, encoding(), charset);
    }

    default String decryptToString(String keyId, String ciphertext) {
        return decryptToString(keyId, ciphertext, encoding(), charset());
    }
}

