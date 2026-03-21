package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.impl.digest.DigestOperations;

import java.nio.charset.Charset;

/**
 * Builder for creating digesters with fluent API to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class DigestBuilder {
    
    private String algorithm;
    private String provider = "";
    private Charset charset = Bruce.DEFAULT_CHARSET;
    private Bruce.Encoding encoding = Bruce.DEFAULT_ENCODING;
    
    DigestBuilder() {
        // package-private constructor
    }
    
    /**
     * Sets the digest algorithm.
     * 
     * @param algorithm the algorithm (e.g., "SHA-256", "MD5")
     * @return this builder
     */
    public DigestBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }
    
    /**
     * Sets the cryptographic provider.
     * 
     * @param provider the provider (e.g., "BC" for Bouncy Castle)
     * @return this builder
     */
    public DigestBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }
    
    /**
     * Sets the charset for string encoding.
     * 
     * @param charset the charset
     * @return this builder
     */
    public DigestBuilder charset(Charset charset) {
        this.charset = charset;
        return this;
    }
    
    /**
     * Sets the encoding for digest output.
     * 
     * @param encoding the encoding
     * @return this builder
     */
    public DigestBuilder encoding(Bruce.Encoding encoding) {
        this.encoding = encoding;
        return this;
    }
    
    public Digester build() {
        validateParameters();
        return DigestOperations.createDigester(algorithm, provider, charset, encoding);
    }
    
    private void validateParameters() {
        if (algorithm == null) {
            throw new BruceException("algorithm is required for digester");
        }
    }
}
