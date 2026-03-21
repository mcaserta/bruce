package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptorByKey;
import com.mirkocaserta.bruce.impl.util.Providers;

import java.security.Key;
import java.security.Provider;
import java.util.Map;

/**
 * Implementation class for asymmetric cipher operations.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class AsymmetricCipherOperations {

    private AsymmetricCipherOperations() {}

    /**
     * Creates an asymmetric encryptor bound to a single key.
     *
     * @param key asymmetric encryption key
     * @param algorithm cipher algorithm/transformation
     * @param provider provider name, or empty for JVM default
     * @return configured encryptor
     */
    public static AsymmetricEncryptor createEncryptor(Key key, String algorithm, String provider) {
        Provider resolvedProvider = Providers.resolve(provider);
        return plaintext -> Bytes.from(crypt(key, algorithm, resolvedProvider, javax.crypto.Cipher.ENCRYPT_MODE, plaintext.asBytes(), "encrypting"));
    }

    /**
     * Creates an asymmetric decryptor bound to a single key.
     *
     * @param key asymmetric decryption key
     * @param algorithm cipher algorithm/transformation
     * @param provider provider name, or empty for JVM default
     * @return configured decryptor
     */
    public static AsymmetricDecryptor createDecryptor(Key key, String algorithm, String provider) {
        Provider resolvedProvider = Providers.resolve(provider);
        return ciphertext -> Bytes.from(crypt(key, algorithm, resolvedProvider, javax.crypto.Cipher.DECRYPT_MODE, ciphertext.asBytes(), "decrypting"));
    }

    /**
     * Creates an asymmetric encryptor that resolves keys by id at call time.
     *
     * @param keys map of key-id to asymmetric encryption key
     * @param algorithm cipher algorithm/transformation
     * @param provider provider name, or empty for JVM default
     * @return configured by-key encryptor
     */
    public static AsymmetricEncryptorByKey createEncryptorByKey(Map<String, Key> keys, String algorithm, String provider) {
        return (keyId, plaintext) -> createEncryptor(resolveKey(keys, keyId), algorithm, provider).encrypt(plaintext);
    }

    /**
     * Creates an asymmetric decryptor that resolves keys by id at call time.
     *
     * @param keys map of key-id to asymmetric decryption key
     * @param algorithm cipher algorithm/transformation
     * @param provider provider name, or empty for JVM default
     * @return configured by-key decryptor
     */
    public static AsymmetricDecryptorByKey createDecryptorByKey(Map<String, Key> keys, String algorithm, String provider) {
        return (keyId, ciphertext) -> createDecryptor(resolveKey(keys, keyId), algorithm, provider).decrypt(ciphertext);
    }

    private static Key resolveKey(Map<String, Key> keys, String keyId) {
        var key = keys.get(keyId);
        if (key == null) {
            throw new BruceException(String.format("no such key: %s", keyId));
        }
        return key;
    }

    private static byte[] crypt(Key key, String algorithm, Provider provider, int mode, byte[] message, String operation) {
        try {
            var cipher = provider == null
                    ? javax.crypto.Cipher.getInstance(algorithm)
                    : javax.crypto.Cipher.getInstance(algorithm, provider);
            cipher.init(mode, key);
            return cipher.doFinal(message);
        } catch (Exception e) {
            throw new BruceException(String.format("error %s message", operation), e);
        }
    }
}
