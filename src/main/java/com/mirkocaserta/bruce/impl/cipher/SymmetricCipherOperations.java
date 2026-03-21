package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptorByKey;
import com.mirkocaserta.bruce.impl.util.Providers;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Implementation class for symmetric cipher operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class SymmetricCipherOperations {

    private SymmetricCipherOperations() {
        // utility class
    }

    public static SymmetricEncryptor createEncryptor(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return new SymmetricEncryptor() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] encrypt(byte[] iv, byte[] plaintext) {
                return crypt(key, keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.ENCRYPT_MODE, iv, plaintext);
            }
        };
    }

    public static SymmetricDecryptor createDecryptor(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return new SymmetricDecryptor() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] decrypt(byte[] iv, byte[] ciphertext) {
                return crypt(key, keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.DECRYPT_MODE, iv, ciphertext);
            }
        };
    }

    public static SymmetricEncryptorByKey createEncryptorByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return new SymmetricEncryptorByKey() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext) {
                return crypt(key, keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.ENCRYPT_MODE, iv, plaintext);
            }
        };
    }

    public static SymmetricDecryptorByKey createDecryptorByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        return new SymmetricDecryptorByKey() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext) {
                return crypt(key, keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.DECRYPT_MODE, iv, ciphertext);
            }
        };
    }

    private static byte[] crypt(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, int mode, byte[] iv, byte[] message) {
        Provider resolvedProvider = Providers.resolve(provider);
        try {
            var initializationVectorSpec = new IvParameterSpec(iv);
            var secretKey = new SecretKeySpec(key, keyAlgorithm);
            var cipher = resolvedProvider == null
                    ? javax.crypto.Cipher.getInstance(cipherAlgorithm)
                    : javax.crypto.Cipher.getInstance(cipherAlgorithm, resolvedProvider);
            cipher.init(mode, secretKey, initializationVectorSpec);
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException e) {
            throw new BruceException("error encrypting/decrypting message", e);
        }
    }
}
