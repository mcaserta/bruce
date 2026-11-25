package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptorByKey;
import com.mirkocaserta.bruce.impl.util.Providers;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Locale;

/**
 * Implementation class for symmetric cipher operations.
 *
 * @author Mirko Caserta (info@mirkocaserta.com)
 */
public final class SymmetricCipherOperations {

    private static final int GCM_TAG_LENGTH_BITS = 128;

    private SymmetricCipherOperations() {}

    /**
     * Creates a symmetric encryptor bound to a fixed key.
     *
     * @param key raw symmetric key bytes
     * @param keyAlgorithm key algorithm (for example AES)
     * @param cipherAlgorithm cipher transformation
     * @param provider provider name, or empty for JVM default
     * @return configured encryptor
     */
    public static SymmetricEncryptor createEncryptor(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider) {
        return (iv, plaintext) -> Bytes.from(crypt(key, keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.ENCRYPT_MODE, iv.asBytes(), plaintext.asBytes()));
    }

    /**
     * Creates a symmetric decryptor bound to a fixed key.
     *
     * @param key raw symmetric key bytes
     * @param keyAlgorithm key algorithm (for example AES)
     * @param cipherAlgorithm cipher transformation
     * @param provider provider name, or empty for JVM default
     * @return configured decryptor
     */
    public static SymmetricDecryptor createDecryptor(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider) {
        return (iv, ciphertext) -> Bytes.from(crypt(key, keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.DECRYPT_MODE, iv.asBytes(), ciphertext.asBytes()));
    }

    /**
     * Creates a symmetric encryptor that receives the key at call time.
     *
     * @param keyAlgorithm key algorithm (for example AES)
     * @param cipherAlgorithm cipher transformation
     * @param provider provider name, or empty for JVM default
     * @return configured by-key encryptor
     */
    public static SymmetricEncryptorByKey createEncryptorByKey(String keyAlgorithm, String cipherAlgorithm, String provider) {
        return (key, iv, plaintext) -> Bytes.from(crypt(key.asBytes(), keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.ENCRYPT_MODE, iv.asBytes(), plaintext.asBytes()));
    }

    /**
     * Creates a symmetric decryptor that receives the key at call time.
     *
     * @param keyAlgorithm key algorithm (for example AES)
     * @param cipherAlgorithm cipher transformation
     * @param provider provider name, or empty for JVM default
     * @return configured by-key decryptor
     */
    public static SymmetricDecryptorByKey createDecryptorByKey(String keyAlgorithm, String cipherAlgorithm, String provider) {
        return (key, iv, ciphertext) -> Bytes.from(crypt(key.asBytes(), keyAlgorithm, cipherAlgorithm, provider, javax.crypto.Cipher.DECRYPT_MODE, iv.asBytes(), ciphertext.asBytes()));
    }

    private static byte[] crypt(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, int mode, byte[] iv, byte[] message) {
        Provider resolvedProvider = Providers.resolve(provider);
        try {
            var secretKey = new SecretKeySpec(key, keyAlgorithm);
            var cipher = resolvedProvider == null
                    ? javax.crypto.Cipher.getInstance(cipherAlgorithm)
                    : javax.crypto.Cipher.getInstance(cipherAlgorithm, resolvedProvider);
            AlgorithmParameterSpec parameters = parametersFor(cipherAlgorithm, iv);
            if (parameters == null) {
                cipher.init(mode, secretKey);
            } else {
                cipher.init(mode, secretKey, parameters);
            }
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException e) {
            throw new BruceException("error encrypting/decrypting message", e);
        }
    }

    /**
     * Picks the parameter spec the transformation's mode expects: a 128-bit tag
     * {@link GCMParameterSpec} for GCM, none for ECB, an {@link IvParameterSpec}
     * for other modes and for {@code ChaCha20-Poly1305} (the IV is its 12-byte
     * nonce). A transformation without a mode gets the provider default and the
     * IV is ignored, except plain {@code ChaCha20}, which is rejected: the
     * provider would make up a nonce of its own and the ciphertext could not be
     * decrypted.
     */
    static AlgorithmParameterSpec parametersFor(String cipherAlgorithm, byte[] iv) {
        String[] parts = cipherAlgorithm.split("/");
        if (parts.length < 2) {
            String name = parts[0].trim().toUpperCase(Locale.ROOT);
            return switch (name) {
                case "CHACHA20-POLY1305" -> new IvParameterSpec(iv);
                case "CHACHA20" -> throw new BruceException(
                        "unauthenticated ChaCha20 is not supported, use ChaCha20-Poly1305");
                default -> null;
            };
        }
        String cipherMode = parts[1].trim().toUpperCase(Locale.ROOT);
        return switch (cipherMode) {
            case "ECB" -> null;
            case "GCM" -> new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            default -> new IvParameterSpec(iv);
        };
    }
}
