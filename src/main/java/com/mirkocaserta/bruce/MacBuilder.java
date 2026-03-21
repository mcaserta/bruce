package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.mac.Mac;
import com.mirkocaserta.bruce.impl.mac.MacOperations;

import java.security.Key;

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
     * Builds a MAC generator.
     *
     * @return configured {@link Mac}
     */
    public Mac build() {
        validateParameters();
        return MacOperations.createMac(key, algorithm, provider);
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
