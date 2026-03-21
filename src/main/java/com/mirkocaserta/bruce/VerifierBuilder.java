package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;
import com.mirkocaserta.bruce.impl.signature.SignatureOperations;

import java.security.PublicKey;
import java.util.Map;

/**
 * Builder for creating {@link Verifier} and {@link VerifierByKey} instances.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class VerifierBuilder {

    private PublicKey publicKey;
    private Map<String, PublicKey> publicKeyMap;
    private String algorithm;
    private String provider = "";

    VerifierBuilder() {}

    /**
     * Sets the public key for verification.
     *
     * @param publicKey public key used to verify signatures
     * @return this builder
     */
    public VerifierBuilder key(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /**
     * Sets a map of public keys for runtime key selection.
     *
     * @param publicKeyMap map of key-id to public key
     * @return this builder
     */
    public VerifierBuilder keys(Map<String, PublicKey> publicKeyMap) {
        this.publicKeyMap = publicKeyMap;
        return this;
    }

    /**
     * Sets the verification algorithm (e.g., {@code "SHA256withRSA"}).
     *
     * @param algorithm signature algorithm
     * @return this builder
     */
    public VerifierBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the cryptographic provider (e.g., {@code "BC"} for Bouncy Castle).
     *
     * @param provider provider name, or {@code null} / empty for JVM default
     * @return this builder
     */
    public VerifierBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    /**
     * Builds a verifier using a single preconfigured key.
     *
     * @return configured {@link Verifier}
     */
    public Verifier build() {
        validateSingleKeyVerifier();
        return SignatureOperations.createVerifier(publicKey, algorithm, provider);
    }

    /**
     * Builds a verifier that selects a key by id at call time.
     *
     * @return configured {@link VerifierByKey}
     */
    public VerifierByKey buildByKey() {
        validateMultiKeyVerifier();
        return SignatureOperations.createVerifierByKey(publicKeyMap, algorithm, provider);
    }

    private void validateSingleKeyVerifier() {
        if (publicKey == null) throw new BruceException("publicKey is required for single key verifier");
        if (algorithm == null) throw new BruceException("algorithm is required for verifier");
    }

    private void validateMultiKeyVerifier() {
        if (publicKeyMap == null || publicKeyMap.isEmpty()) throw new BruceException("publicKeyMap is required for multi-key verifier");
        if (algorithm == null) throw new BruceException("algorithm is required for verifier");
    }
}
