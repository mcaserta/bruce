package com.mirkocaserta.bruce.impl.cipher;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipher;
import com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Implementation class for asymmetric cipher operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class AsymmetricCipherOperations {
    
    private static final String BLANK = "";
    private static final ConcurrentMap<String, Cipher> cipherCache = new ConcurrentHashMap<>();
    
    private AsymmetricCipherOperations() {
        // utility class
    }
    
    public static Cipher createCipher(Key key, String algorithm, Mode mode) {
        return createCipher(key, algorithm, BLANK, mode);
    }
    
    public static Cipher createCipher(Key key, String algorithm, String provider, Mode mode) {
        if (mode == null) {
            throw new BruceException("mode cannot be null");
        }

        return message -> {
            try {
                var cipher = provider == null || provider.isBlank()
                        ? javax.crypto.Cipher.getInstance(algorithm)
                        : javax.crypto.Cipher.getInstance(algorithm, provider);
                if (mode == Mode.ENCRYPT) {
                    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
                } else if (mode == Mode.DECRYPT) {
                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
                }
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new BruceException(String.format("error encrypting/decrypting message; mode=%s", mode), e);
            }
        };
    }
    
    public static CipherByKey createCipherByKey(Map<String, Key> keys, String algorithm) {
        return createCipherByKey(keys, algorithm, BLANK);
    }
    
    public static CipherByKey createCipherByKey(Map<String, Key> keys, String algorithm, String provider) {
        // we use a cipher cache here as getting a new one each time is a bit expensive
        return (keyId, mode, message) -> getCipher(keys, keyId, algorithm, provider, mode).encrypt(message);
    }
    
    public static EncodingCipher createEncodingCipher(Key key, String algorithm, Mode mode, Bruce.Encoding encoding, Charset charset) {
        return createEncodingCipher(key, algorithm, BLANK, mode, encoding, charset);
    }
    
    public static EncodingCipher createEncodingCipher(Key key, String algorithm, String provider, Mode mode, Bruce.Encoding encoding, Charset charset) {
        var cipher = createCipher(key, algorithm, provider, mode);
        return message -> crypt(cipher, message, mode, encoding, charset);
    }
    
    public static EncodingCipherByKey createEncodingCipherByKey(Map<String, Key> keys, String algorithm, Bruce.Encoding encoding, Charset charset) {
        return createEncodingCipherByKey(keys, algorithm, BLANK, encoding, charset);
    }
    
    public static EncodingCipherByKey createEncodingCipherByKey(Map<String, Key> keys, String algorithm, String provider, Bruce.Encoding encoding, Charset charset) {
        return (keyId, mode, message) -> {
            var cipher = getCipher(keys, keyId, algorithm, provider, mode);
            return crypt(cipher, message, mode, encoding, charset);
        };
    }
    
    private static String crypt(Cipher cipher, String message, Mode mode, Bruce.Encoding encoding, Charset charset) {
        if (mode == Mode.ENCRYPT) {
            return EncodingUtils.encode(encoding, cipher.encrypt(message.getBytes(charset)));
        } else if (mode == Mode.DECRYPT) {
            return new String(cipher.encrypt(EncodingUtils.decode(encoding, message)), charset);
        }
        throw new BruceException("no such mode");
    }
    
    private static Cipher getCipher(Map<String, Key> keys, String keyId, String algorithm, String provider, Mode mode) {
        return cipherCache.computeIfAbsent(cipherCacheKey(keyId, algorithm, provider, mode), ignored -> {
            var key = keys.get(keyId);
            if (key == null) {
                throw new BruceException(String.format("no such key: %s", keyId));
            }
            return createCipher(key, algorithm, provider, mode);
        });
    }
    
    private static String cipherCacheKey(String keyId, String algorithm, String provider, Mode mode) {
        return keyId + "::" + algorithm + "::" + provider + "::" + mode;
    }
}