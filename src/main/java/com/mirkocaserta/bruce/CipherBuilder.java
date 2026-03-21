package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.asymmetric.AsymmetricEncryptorByKey;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricDecryptorByKey;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptor;
import com.mirkocaserta.bruce.cipher.symmetric.SymmetricEncryptorByKey;
import com.mirkocaserta.bruce.impl.cipher.AsymmetricCipherOperations;
import com.mirkocaserta.bruce.impl.cipher.SymmetricCipherOperations;

import java.nio.charset.Charset;
import java.security.Key;
import java.util.Map;

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
    private Charset charset = Bruce.DEFAULT_CHARSET;
    private Bruce.Encoding encoding = Bruce.DEFAULT_ENCODING;
    
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
    
    public SymmetricEncryptor buildSymmetricEncryptor() {
        validateFixedSymmetricCipher();
        return SymmetricCipherOperations.createEncryptor(resolveFixedSymmetricKey(), keyAlgorithm, cipherAlgorithm, provider, charset, encoding);
    }

    public SymmetricDecryptor buildSymmetricDecryptor() {
        validateFixedSymmetricCipher();
        return SymmetricCipherOperations.createDecryptor(resolveFixedSymmetricKey(), keyAlgorithm, cipherAlgorithm, provider, charset, encoding);
    }

    public SymmetricEncryptorByKey buildSymmetricEncryptorByKey() {
        validateSymmetricByKeyCipher();
        return SymmetricCipherOperations.createEncryptorByKey(keyAlgorithm, cipherAlgorithm, provider, charset, encoding);
    }

    public SymmetricDecryptorByKey buildSymmetricDecryptorByKey() {
        validateSymmetricByKeyCipher();
        return SymmetricCipherOperations.createDecryptorByKey(keyAlgorithm, cipherAlgorithm, provider, charset, encoding);
    }

    public AsymmetricEncryptor buildAsymmetricEncryptor() {
        validateAsymmetricCipher();
        return AsymmetricCipherOperations.createEncryptor(asymmetricKey, cipherAlgorithm, provider, charset, encoding);
    }

    public AsymmetricDecryptor buildAsymmetricDecryptor() {
        validateAsymmetricCipher();
        return AsymmetricCipherOperations.createDecryptor(asymmetricKey, cipherAlgorithm, provider, charset, encoding);
    }

    public AsymmetricEncryptorByKey buildAsymmetricEncryptorByKey() {
        validateAsymmetricByKeyCipher();
        return AsymmetricCipherOperations.createEncryptorByKey(asymmetricKeys, cipherAlgorithm, provider, charset, encoding);
    }

    public AsymmetricDecryptorByKey buildAsymmetricDecryptorByKey() {
        validateAsymmetricByKeyCipher();
        return AsymmetricCipherOperations.createDecryptorByKey(asymmetricKeys, cipherAlgorithm, provider, charset, encoding);
    }
    
    private void validateFixedSymmetricCipher() {
        if (key == null && rawKey == null) {
            throw new BruceException("key is required for symmetric cipher");
        }
        if (keyAlgorithm == null) {
            throw new BruceException("keyAlgorithm is required for symmetric cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("cipherAlgorithm is required for symmetric cipher");
        }
    }
    
    private void validateAsymmetricCipher() {
        if (asymmetricKey == null) {
            throw new BruceException("key is required for asymmetric cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("algorithm is required for asymmetric cipher");
        }
    }

    private void validateSymmetricByKeyCipher() {
        if (keyAlgorithm == null) {
            throw new BruceException("keyAlgorithm is required for symmetric by-key cipher");
        }
        if (cipherAlgorithm == null) {
            throw new BruceException("cipherAlgorithm is required for symmetric by-key cipher");
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

    private byte[] resolveFixedSymmetricKey() {
        return rawKey != null ? rawKey : com.mirkocaserta.bruce.impl.util.EncodingUtils.decode(encoding, key);
    }
}
