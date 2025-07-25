package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;

import java.nio.charset.Charset;
import java.security.Key;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Builder for creating ciphers with fluent API to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class CipherBuilder {
    
    private String key;
    private Key asymmetricKey;
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
        return Bruce.cipher(key, keyAlgorithm, cipherAlgorithm, provider, mode, charset, encoding);
    }
    
    /**
     * Builds an asymmetric encoding cipher.
     * 
     * @return the cipher
     * @throws BruceException if required parameters are missing
     */
    public com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher buildAsymmetric() {
        validateAsymmetricCipher();
        return Bruce.cipher(asymmetricKey, cipherAlgorithm, provider, mode, encoding, charset);
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
}