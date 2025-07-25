package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.signature.EncodingVerifier;
import com.mirkocaserta.bruce.signature.EncodingVerifierByKey;
import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;

import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Builder for creating verifiers with fluent API to reduce parameter overload.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class VerifierBuilder {
    
    private PublicKey publicKey;
    private Map<String, PublicKey> publicKeyMap;
    private String algorithm;
    private String provider = "";
    private Charset charset = UTF_8;
    private Bruce.Encoding encoding = Bruce.Encoding.BASE64;
    
    VerifierBuilder() {
        // package-private constructor
    }
    
    /**
     * Sets the public key for verification.
     * 
     * @param publicKey the public key
     * @return this builder
     */
    public VerifierBuilder key(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }
    
    /**
     * Sets a map of public keys for runtime key selection.
     * 
     * @param publicKeyMap the public key map
     * @return this builder
     */
    public VerifierBuilder keys(Map<String, PublicKey> publicKeyMap) {
        this.publicKeyMap = publicKeyMap;
        return this;
    }
    
    /**
     * Sets the verification algorithm.
     * 
     * @param algorithm the algorithm (e.g., "SHA256withRSA")
     * @return this builder
     */
    public VerifierBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }
    
    /**
     * Sets the cryptographic provider.
     * 
     * @param provider the provider (e.g., "BC" for Bouncy Castle)
     * @return this builder
     */
    public VerifierBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }
    
    /**
     * Sets the charset for string encoding.
     * 
     * @param charset the charset
     * @return this builder
     */
    public VerifierBuilder charset(Charset charset) {
        this.charset = charset;
        return this;
    }
    
    /**
     * Sets the encoding for signature input.
     * 
     * @param encoding the encoding
     * @return this builder
     */
    public VerifierBuilder encoding(Bruce.Encoding encoding) {
        this.encoding = encoding;
        return this;
    }
    
    /**
     * Builds a raw verifier with a single key.
     * 
     * @return the verifier
     * @throws BruceException if required parameters are missing
     */
    public Verifier buildRaw() {
        validateSingleKeyVerifier();
        return Bruce.verifier(publicKey, algorithm, provider);
    }
    
    /**
     * Builds an encoding verifier with a single key.
     * 
     * @return the verifier
     * @throws BruceException if required parameters are missing
     */
    public EncodingVerifier build() {
        validateSingleKeyVerifier();
        return Bruce.verifier(publicKey, algorithm, provider, charset, encoding);
    }
    
    /**
     * Builds a raw verifier with multiple keys for runtime selection.
     * 
     * @return the verifier
     * @throws BruceException if required parameters are missing
     */
    public VerifierByKey buildRawByKey() {
        validateMultiKeyVerifier();
        return Bruce.verifier(publicKeyMap, algorithm, provider);
    }
    
    /**
     * Builds an encoding verifier with multiple keys for runtime selection.
     * 
     * @return the verifier
     * @throws BruceException if required parameters are missing
     */
    public EncodingVerifierByKey buildByKey() {
        validateMultiKeyVerifier();
        return Bruce.verifier(publicKeyMap, algorithm, provider, charset, encoding);
    }
    
    private void validateSingleKeyVerifier() {
        if (publicKey == null) {
            throw new BruceException("publicKey is required for single key verifier");
        }
        if (algorithm == null) {
            throw new BruceException("algorithm is required for verifier");
        }
    }
    
    private void validateMultiKeyVerifier() {
        if (publicKeyMap == null || publicKeyMap.isEmpty()) {
            throw new BruceException("publicKeyMap is required for multi-key verifier");
        }
        if (algorithm == null) {
            throw new BruceException("algorithm is required for verifier");
        }
    }
}