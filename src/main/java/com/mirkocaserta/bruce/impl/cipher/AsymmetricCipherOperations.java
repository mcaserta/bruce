package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptorByKey;
import com.mirkocaserta.bruce.impl.util.Providers;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.Provider;
import java.util.Map;

/**
 * Implementation class for asymmetric cipher operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class AsymmetricCipherOperations {

    private AsymmetricCipherOperations() {
        // utility class
    }

    public static AsymmetricEncryptor createEncryptor(Key key, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);
        return new AsymmetricEncryptor() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] encrypt(byte[] plaintext) {
                return crypt(key, algorithm, resolvedProvider, javax.crypto.Cipher.ENCRYPT_MODE, plaintext, "encrypting");
            }
        };
    }

    public static AsymmetricDecryptor createDecryptor(Key key, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);
        return new AsymmetricDecryptor() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] decrypt(byte[] ciphertext) {
                return crypt(key, algorithm, resolvedProvider, javax.crypto.Cipher.DECRYPT_MODE, ciphertext, "decrypting");
            }
        };
    }

    public static AsymmetricEncryptorByKey createEncryptorByKey(Map<String, Key> keys, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return new AsymmetricEncryptorByKey() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] encrypt(String keyId, byte[] plaintext) {
                return createEncryptor(resolveKey(keys, keyId), algorithm, provider, charset, encoding).encrypt(plaintext);
            }
        };
    }

    public static AsymmetricDecryptorByKey createDecryptorByKey(Map<String, Key> keys, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return new AsymmetricDecryptorByKey() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] decrypt(String keyId, byte[] ciphertext) {
                return createDecryptor(resolveKey(keys, keyId), algorithm, provider, charset, encoding).decrypt(ciphertext);
            }
        };
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
