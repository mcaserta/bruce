package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.mac.MacOperations;
import com.mirkocaserta.bruce.impl.util.Preconditions;
import com.mirkocaserta.bruce.mac.Mac;

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
     * Sets the MAC algorithm using the type-safe {@link MacAlgorithm} enum.
     *
     * <pre>{@code
     * Mac mac = Bruce.macBuilder()
     *     .key(secretKey)
     *     .algorithm(MacAlgorithm.HMAC_SHA_256)
     *     .build();
     * }</pre>
     *
     * @param algorithm MAC algorithm constant; must not be {@code null}
     * @return this builder
     */
    public MacBuilder algorithm(MacAlgorithm algorithm) {
        Preconditions.requireNonNull(algorithm, "algorithm");
        this.algorithm = algorithm.algorithmName();
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
     * Sets the cryptographic provider from the built-in provider enum.
     *
     * @param provider provider selection, or {@code null} for JVM default
     * @return this builder
     */
    public MacBuilder provider(Bruce.Provider provider) {
        this.provider = provider == null ? "" : provider.providerName();
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
        Preconditions.requireNonNull(key, "key");
        Preconditions.requireNonBlank(algorithm, "algorithm");
    }
}
