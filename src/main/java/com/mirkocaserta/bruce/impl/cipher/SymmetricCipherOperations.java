package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.symmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Implementation class for symmetric cipher operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class SymmetricCipherOperations {
    
    private static final String BLANK = "";
    
    private SymmetricCipherOperations() {
        // utility class
    }
    
    /**
     * Creates a symmetric cipher where the key is selected at runtime via key id.
     *
     * @param keyAlgorithm the key algorithm (e.g., AES)
     * @param cipherAlgorithm the cipher transformation (e.g., AES/CBC/PKCS5Padding)
     * @param mode the operation mode (encrypt/decrypt)
     * @return a cipher interface supporting runtime key selection
     */
    public static CipherByKey createCipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return createCipherByKey(keyAlgorithm, cipherAlgorithm, BLANK, mode);
    }
    
    /**
     * Creates a symmetric cipher where the key is selected at runtime via key id using a specific provider.
     *
     * @param keyAlgorithm the key algorithm (e.g., AES)
     * @param cipherAlgorithm the cipher transformation (e.g., AES/CBC/PKCS5Padding)
     * @param provider the JCA provider name (e.g., "BC")
     * @param mode the operation mode (encrypt/decrypt)
     * @return a cipher interface supporting runtime key selection
     */
    public static CipherByKey createCipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        if (mode == null) {
            throw new BruceException("mode cannot be null");
        }

        return (key, iv, message) -> {
            try {
                var initializationVectorSpec = new IvParameterSpec(iv);
                var spec = new SecretKeySpec(key, keyAlgorithm);
                var cipher = provider == null || provider.isBlank()
                        ? javax.crypto.Cipher.getInstance(cipherAlgorithm)
                        : javax.crypto.Cipher.getInstance(cipherAlgorithm, provider);
                if (mode == Mode.ENCRYPT) {
                    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, spec, initializationVectorSpec);
                } else if (mode == Mode.DECRYPT) {
                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, spec, initializationVectorSpec);
                }
                return cipher.doFinal(message);
            } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IllegalBlockSizeException e) {
                throw new BruceException("error encrypting/decrypting message", e);
            }
        };
    }
    
    /**
     * Creates a symmetric cipher for the given raw key bytes.
     *
     * @param key the raw key bytes
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher transformation
     * @param mode the operation mode (encrypt/decrypt)
     * @return a symmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher createCipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return createCipher(key, keyAlgorithm, cipherAlgorithm, BLANK, mode);
    }
    
    /**
     * Creates a symmetric cipher for the given raw key bytes using a specific provider.
     *
     * @param key the raw key bytes
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher transformation
     * @param provider the JCA provider name (e.g., "BC")
     * @param mode the operation mode (encrypt/decrypt)
     * @return a symmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher createCipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        var cipher = createCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode);
        return (iv, message) -> cipher.encrypt(key, iv, message);
    }
    
    /**
     * Creates a text-based symmetric cipher where the key is selected at runtime via key id.
     *
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher transformation
     * @param mode the operation mode
     * @param charset the message charset
     * @return an encoding cipher with runtime key selection
     */
    public static EncodingCipherByKey createEncodingCipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
        return createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, BLANK, mode, charset);
    }
    
    /**
     * Creates a text-based symmetric cipher where the key is selected at runtime via key id using a specific provider.
     *
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher transformation
     * @param provider the JCA provider name
     * @param mode the operation mode
     * @param charset the message charset
     * @return an encoding cipher with runtime key selection
     */
    public static EncodingCipherByKey createEncodingCipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
        var cipher = createCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode);

        return (key, iv, message, encoding) -> {
            var keyBA = EncodingUtils.decode(encoding, key);
            var ivBA = EncodingUtils.decode(encoding, iv);

            if (mode == Mode.ENCRYPT) {
                return EncodingUtils.encode(encoding, cipher.encrypt(keyBA, ivBA, message.getBytes(charset)));
            } else if (mode == Mode.DECRYPT) {
                return new String(cipher.encrypt(keyBA, ivBA, EncodingUtils.decode(encoding, message)), charset);
            }
            throw new BruceException("no such mode");
        };
    }
    
    /**
     * Creates a text-based symmetric cipher for the given string key.
     *
     * @param key the key as a string
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher transformation
     * @param mode the operation mode
     * @param charset the message charset
     * @param encoding the message encoding
     * @return an encoding symmetric cipher
     */
    public static EncodingCipher createEncodingCipher(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Bruce.Encoding encoding) {
        return createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, BLANK, mode, charset, encoding);
    }
    
    /**
     * Creates a text-based symmetric cipher for the given string key using a specific provider.
     *
     * @param key the key as a string
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher transformation
     * @param provider the JCA provider name
     * @param mode the operation mode
     * @param charset the message charset
     * @param encoding the message encoding
     * @return an encoding symmetric cipher
     */
    public static EncodingCipher createEncodingCipher(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Bruce.Encoding encoding) {
        var cipher = createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
        return (iv, message) -> cipher.encrypt(key, iv, message, encoding);
    }
}