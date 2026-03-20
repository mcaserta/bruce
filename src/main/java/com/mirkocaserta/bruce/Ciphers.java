package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.impl.cipher.AsymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.cipher.SymmetricCipherOperations;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.Map;

/**
 * Feature-focused facade for symmetric and asymmetric cipher operations.
 */
public final class Ciphers {

    private Ciphers() {
        // utility class
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return SymmetricCipherOperations.createCipherByKey(keyAlgorithm, cipherAlgorithm, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return SymmetricCipherOperations.createCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return SymmetricCipherOperations.createCipher(key, keyAlgorithm, cipherAlgorithm, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return SymmetricCipherOperations.createCipher(key, keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
        return SymmetricCipherOperations.createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, mode, charset);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
        return SymmetricCipherOperations.createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Bruce.Encoding encoding) {
        return SymmetricCipherOperations.createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, mode, charset, encoding);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Bruce.Encoding encoding) {
        return SymmetricCipherOperations.createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, provider, mode, charset, encoding);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.Cipher cipher(Key key, String algorithm, Mode mode) {
        return AsymmetricCipherOperations.createCipher(key, algorithm, mode);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.Cipher cipher(Key key, String algorithm, String provider, Mode mode) {
        return AsymmetricCipherOperations.createCipher(key, algorithm, provider, mode);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm) {
        return AsymmetricCipherOperations.createCipherByKey(keys, algorithm);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm, String provider) {
        return AsymmetricCipherOperations.createCipherByKey(keys, algorithm, provider);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, Mode mode, Bruce.Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipher(key, algorithm, mode, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, String provider, Mode mode, Bruce.Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipher(key, algorithm, provider, mode, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, Bruce.Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipherByKey(keys, algorithm, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, String provider, Bruce.Encoding encoding, Charset charset) {
        return AsymmetricCipherOperations.createEncodingCipherByKey(keys, algorithm, provider, encoding, charset);
    }
}
