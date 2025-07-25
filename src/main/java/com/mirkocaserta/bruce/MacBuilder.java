package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;

import java.nio.charset.Charset;
import java.security.Key;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Builder for creating MAC (Message Authentication Code) generators with fluent API 
 * to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class MacBuilder {
    
    private Key key;
    private String algorithm;
    private String provider = "";
    private Charset charset = UTF_8;
    private Bruce.Encoding encoding = Bruce.Encoding.BASE64;
    
    MacBuilder() {
        // package-private constructor
    }
    
    /**
     * Sets the secret key for MAC generation.
     * 
     * @param key the secret key
     * @return this builder
     */
    public MacBuilder key(Key key) {
        this.key = key;
        return this;
    }
    
    /**
     * Sets the MAC algorithm.
     * 
     * @param algorithm the algorithm (e.g., "HmacSHA256", "HmacMD5")
     * @return this builder
     */
    public MacBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }
    
    /**
     * Sets the cryptographic provider.
     * 
     * @param provider the provider (e.g., "BC" for Bouncy Castle)
     * @return this builder
     */
    public MacBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }
    
    /**
     * Sets the charset for string encoding.
     * 
     * @param charset the charset
     * @return this builder
     */
    public MacBuilder charset(Charset charset) {
        this.charset = charset;
        return this;
    }
    
    /**
     * Sets the encoding for MAC output.
     * 
     * @param encoding the encoding
     * @return this builder
     */
    public MacBuilder encoding(Bruce.Encoding encoding) {
        this.encoding = encoding;
        return this;
    }
    
    /**
     * Builds a raw byte array MAC generator.
     * 
     * @return the MAC generator
     * @throws BruceException if required parameters are missing
     */
    public Mac buildRaw() {
        validateParameters();
        return Bruce.mac(key, algorithm, provider);
    }
    
    /**
     * Builds an encoding MAC generator for string messages.
     * 
     * @return the MAC generator
     * @throws BruceException if required parameters are missing
     */
    public EncodingMac build() {
        validateParameters();
        return Bruce.mac(key, algorithm, provider, encoding, charset);
    }
    
    private void validateParameters() {
        if (key == null) {
            throw new BruceException("key is required for MAC generator");
        }
        if (algorithm == null) {
            throw new BruceException("algorithm is required for MAC generator");
        }
    }
}