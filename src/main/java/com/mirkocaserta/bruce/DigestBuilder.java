package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.EncodingDigester;
import com.mirkocaserta.bruce.digest.FileDigester;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Builder for creating digesters with fluent API to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class DigestBuilder {
    
    private String algorithm;
    private String provider = "";
    private Charset charset = UTF_8;
    private Bruce.Encoding encoding = Bruce.Encoding.BASE64;
    
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
    
    /**
     * Builds a raw byte array digester.
     * 
     * @return the digester
     * @throws BruceException if required parameters are missing
     */
    public Digester buildRaw() {
        validateParameters();
        return Bruce.digester(algorithm, provider);
    }
    
    /**
     * Builds an encoding digester for string messages.
     * 
     * @return the digester
     * @throws BruceException if required parameters are missing
     */
    public EncodingDigester build() {
        validateParameters();
        return Bruce.digester(algorithm, provider, encoding, charset);
    }
    
    /**
     * Builds a file digester with encoding.
     * 
     * @return the file digester
     * @throws BruceException if required parameters are missing
     */
    public FileDigester buildFileDigester() {
        validateParameters();
        return Bruce.fileDigester(algorithm, provider, encoding);
    }
    
    private void validateParameters() {
        if (algorithm == null) {
            throw new BruceException("algorithm is required for digester");
        }
    }
}