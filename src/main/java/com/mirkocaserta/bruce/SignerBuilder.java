package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.signature.EncodingSigner;
import com.mirkocaserta.bruce.signature.EncodingSignerByKey;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Builder for creating signers with fluent API to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class SignerBuilder {
    
    private PrivateKey privateKey;
    private Map<String, PrivateKey> privateKeyMap;
    private String algorithm;
    private String provider = "";
    private Charset charset = UTF_8;
    private Bruce.Encoding encoding = Bruce.Encoding.BASE64;
    
    SignerBuilder() {
        // package-private constructor
    }
    
    /**
     * Sets the private key for signing.
     * 
     * @param privateKey the private key
     * @return this builder
     */
    public SignerBuilder key(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }
    
    /**
     * Sets a map of private keys for runtime key selection.
     * 
     * @param privateKeyMap the private key map
     * @return this builder
     */
    public SignerBuilder keys(Map<String, PrivateKey> privateKeyMap) {
        this.privateKeyMap = privateKeyMap;
        return this;
    }
    
    /**
     * Sets the signing algorithm.
     * 
     * @param algorithm the algorithm (e.g., "SHA256withRSA")
     * @return this builder
     */
    public SignerBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }
    
    /**
     * Sets the cryptographic provider.
     * 
     * @param provider the provider (e.g., "BC" for Bouncy Castle)
     * @return this builder
     */
    public SignerBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }
    
    /**
     * Sets the charset for string encoding.
     * 
     * @param charset the charset
     * @return this builder
     */
    public SignerBuilder charset(Charset charset) {
        this.charset = charset;
        return this;
    }
    
    /**
     * Sets the encoding for signature output.
     * 
     * @param encoding the encoding
     * @return this builder
     */
    public SignerBuilder encoding(Bruce.Encoding encoding) {
        this.encoding = encoding;
        return this;
    }
    
    /**
     * Builds an encoding signer with a single key.
     * 
     * @return the signer
     * @throws BruceException if required parameters are missing
     */
    public EncodingSigner build() {
        validateSingleKeySigner();
        return Bruce.signer(privateKey, algorithm, provider, charset, encoding);
    }
    
    /**
     * Builds an encoding signer with multiple keys for runtime selection.
     * 
     * @return the signer
     * @throws BruceException if required parameters are missing
     */
    public EncodingSignerByKey buildByKey() {
        validateMultiKeySigner();
        return Bruce.signer(privateKeyMap, algorithm, provider, charset, encoding);
    }
    
    private void validateSingleKeySigner() {
        if (privateKey == null) {
            throw new BruceException("privateKey is required for single key signer");
        }
        if (algorithm == null) {
            throw new BruceException("algorithm is required for signer");
        }
    }
    
    private void validateMultiKeySigner() {
        if (privateKeyMap == null || privateKeyMap.isEmpty()) {
            throw new BruceException("privateKeyMap is required for multi-key signer");
        }
        if (algorithm == null) {
            throw new BruceException("algorithm is required for signer");
        }
    }
}