package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.impl.cipher.AsymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.cipher.SymmetricCipherOperations;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Builder for creating ciphers with fluent API to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class CipherBuilder {
    
    private String key;
    private byte[] rawKey;
    private Key asymmetricKey;
    private Map<String, Key> asymmetricKeys;
    private String keyAlgorithm;
    private String cipherAlgorithm;
    private String provider = "";
    private Mode mode;
    private Charset charset = UTF_8;
    private Bruce.Encoding encoding = Bruce.Encoding.BASE64;
    
    CipherBuilder() {
        // package-private constructor
    }
    
    /**
     * Sets the symmetric cipher key (encoded string).
     * 
     * @param key the cipher key
     * @return this builder
     */
    public CipherBuilder key(String key) {
        this.key = key;
        return this;
    }

    /**
     * Sets the symmetric cipher key as raw bytes.
     *
     * @param key the cipher key
     * @return this builder
     */
    public CipherBuilder key(byte[] key) {
        this.rawKey = key;
        return this;
    }
    
    /**
     * Sets the asymmetric cipher key.
     * 
     * @param key the cipher key
     * @return this builder
     */
    public CipherBuilder key(Key key) {
        this.asymmetricKey = key;
        return this;
    }

    /**
     * Sets a map of asymmetric keys for runtime key selection.
     *
     * @param keys the keys map
     * @return this builder
     */
    public CipherBuilder keys(Map<String, Key> keys) {
        this.asymmetricKeys = keys;
        return this;
    }
    
    /**
     * Sets the key algorithm for symmetric ciphers.
     * 
     * @param keyAlgorithm the key algorithm
     * @return this builder
     */
    public CipherBuilder keyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        return this;
    }
    
    /**
     * Sets the cipher algorithm.
     * 
     * @param cipherAlgorithm the cipher algorithm
     * @return this builder
     */
    public CipherBuilder algorithm(String cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }
    
    /**
     * Sets both key and cipher algorithms (convenience method).
     * 
     * @param keyAlgorithm the key algorithm
     * @param cipherAlgorithm the cipher algorithm
     * @return this builder
     */
    public CipherBuilder algorithms(String keyAlgorithm, String cipherAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        this.cipherAlgorithm = cipherAlgorithm;
        return this;
    }
    
    /**
     * Sets the cryptographic provider.
     * 
     * @param provider the provider (e.g., "BC" for Bouncy Castle)
     * @return this builder
     */
    public CipherBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }
    
    /**
     * Sets the cipher mode (encrypt/decrypt).
     * 
     * @param mode the cipher mode
     * @return this builder
     */
    public CipherBuilder mode(Mode mode) {
        this.mode = mode;
        return this;
    }
    
    /**
     * Sets the charset for string encoding/decoding.
     * 
     * @param charset the charset
     * @return this builder
     */
    public CipherBuilder charset(Charset charset) {
        this.charset = charset;
        return this;
    }
    
    /**
     * Sets the encoding for keys and output.
     * 
     * @param encoding the encoding
     * @return this builder
     */
    public CipherBuilder encoding(Bruce.Encoding encoding) {
        this.encoding = encoding;
        return this;
    }
    
    /**
     * Builds a symmetric encoding cipher.
     * 
     * @return the cipher
     * @throws BruceException if required parameters are missing
     */
    public com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher buildSymmetric() {
        validateSymmetricCipher();
        return provider.isBlank()
                ? SymmetricCipherOperations.createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, mode, charset, encoding)
                : SymmetricCipherOperations.createEncodingCipher(key, keyAlgorithm, cipherAlgorithm, provider, mode, charset, encoding);
    }

    /**
     * Builds a symmetric raw cipher.
     *
     * @return the cipher
     */
    public com.mirkocaserta.bruce.cipher.symmetric.SymmetricCipher buildSymmetricRaw() {
        validateSymmetricRawCipher();
        return provider.isBlank()
                ? SymmetricCipherOperations.createCipher(rawKey, keyAlgorithm, cipherAlgorithm, mode)
                : SymmetricCipherOperations.createCipher(rawKey, keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    /**
     * Builds a symmetric raw cipher where the key is selected at runtime.
     *
     * @return the cipher by key
     */
    public com.mirkocaserta.bruce.cipher.symmetric.CipherByKey buildSymmetricRawByKey() {
        validateSymmetricByKeyCipher();
        return provider.isBlank()
                ? SymmetricCipherOperations.createCipherByKey(keyAlgorithm, cipherAlgorithm, mode)
                : SymmetricCipherOperations.createCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode);
    }

    /**
     * Builds a symmetric encoding cipher where the key is selected at runtime.
     *
     * @return the encoding cipher by key
     */
    public com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey buildSymmetricByKey() {
        validateSymmetricByKeyCipher();
        return provider.isBlank()
                ? SymmetricCipherOperations.createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, mode, charset)
                : SymmetricCipherOperations.createEncodingCipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
    }
    
    /**
     * Builds an asymmetric encoding cipher.
     * 
     * @return the cipher
     * @throws BruceException if required parameters are missing
     */
    public com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher buildAsymmetric() {
        validateAsymmetricCipher();
        return provider.isBlank()
                ? AsymmetricCipherOperations.createEncodingCipher(asymmetricKey, cipherAlgorithm, mode, encoding, charset)
                : AsymmetricCipherOperations.createEncodingCipher(asymmetricKey, cipherAlgorithm, provider, mode, encoding, charset);
    }

    /**
     * Builds an asymmetric raw cipher.
     *
     * @return the cipher
     */
    public com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricCipher buildAsymmetricRaw() {
        validateAsymmetricCipher();
        return provider.isBlank()
                ? AsymmetricCipherOperations.createCipher(asymmetricKey, cipherAlgorithm, mode)
                : AsymmetricCipherOperations.createCipher(asymmetricKey, cipherAlgorithm, provider, mode);
    }

    /**
     * Builds an asymmetric raw cipher with runtime key selection.
     *
     * @return the cipher by key
     */
    public com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey buildAsymmetricRawByKey() {
        validateAsymmetricByKeyCipher();
        return provider.isBlank()
                ? AsymmetricCipherOperations.createCipherByKey(asymmetricKeys, cipherAlgorithm)
                : AsymmetricCipherOperations.createCipherByKey(asymmetricKeys, cipherAlgorithm, provider);
    }

    /**
     * Builds an asymmetric encoding cipher with runtime key selection.
     *
     * @return the encoding cipher by key
     */
    public com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey buildAsymmetricByKey() {
        validateAsymmetricByKeyCipher();
        return provider.isBlank()
                ? AsymmetricCipherOperations.createEncodingCipherByKey(asymmetricKeys, cipherAlgorithm, encoding, charset)
                : AsymmetricCipherOperations.createEncodingCipherByKey(asymmetricKeys, cipherAlgorithm, provider, encoding, charset);
    }
    
    private void validateSymmetricCipher() {
        if (key == null) {
            throw new BruceException("key is required for symmetric cipher");
        }
        if (keyAlgorithm == null) {
            throw new BruceException("keyAlgorithm is required for symmetric cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("cipherAlgorithm is required for symmetric cipher");
        }
        if (mode == null) {
            throw new BruceException("mode is required for cipher");
        }
    }
    
    private void validateAsymmetricCipher() {
        if (asymmetricKey == null) {
            throw new BruceException("key is required for asymmetric cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("algorithm is required for asymmetric cipher");
        }
        if (mode == null) {
            throw new BruceException("mode is required for cipher");
        }
    }

    private void validateSymmetricRawCipher() {
        if (rawKey == null) {
            throw new BruceException("raw key is required for symmetric cipher");
        }
        if (keyAlgorithm == null) {
            throw new BruceException("keyAlgorithm is required for symmetric cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("cipherAlgorithm is required for symmetric cipher");
        }
        if (mode == null) {
            throw new BruceException("mode is required for cipher");
        }
    }

    private void validateSymmetricByKeyCipher() {
        if (keyAlgorithm == null) {
            throw new BruceException("keyAlgorithm is required for symmetric by-key cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("cipherAlgorithm is required for symmetric by-key cipher");
        }
        if (mode == null) {
            throw new BruceException("mode is required for cipher");
        }
    }

    private void validateAsymmetricByKeyCipher() {
        if (asymmetricKeys == null || asymmetricKeys.isEmpty()) {
            throw new BruceException("keys are required for asymmetric by-key cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("algorithm is required for asymmetric by-key cipher");
        }
    }
}
