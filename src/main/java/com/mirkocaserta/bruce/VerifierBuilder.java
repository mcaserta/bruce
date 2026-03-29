package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.signature.SignatureOperations;
import com.mirkocaserta.bruce.impl.util.Preconditions;
import com.mirkocaserta.bruce.signature.Verifier;
import com.mirkocaserta.bruce.signature.VerifierByKey;

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
<<<<<<< HEAD
     * Sets the verification algorithm using the type-safe {@link SignatureAlgorithm} enum.
     *
     * <pre>{@code
     * Verifier verifier = Bruce.verifierBuilder()
     *     .key(publicKey)
     *     .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
     *     .build();
     * }</pre>
     *
     * @param algorithm signature algorithm constant; must not be {@code null}
     * @return this builder
     */
    public VerifierBuilder algorithm(SignatureAlgorithm algorithm) {
        Preconditions.requireNonNull(algorithm, "algorithm");
        this.algorithm = algorithm.algorithmName();
||||||| parent of 6848bc6 (Add #205 phase 1 algorithm enums for builder APIs)
=======
     * Sets the verification algorithm via enum.
     *
     * @param algorithm signature algorithm enum value
     * @return this builder
     */
    public VerifierBuilder algorithm(Bruce.SignatureAlgorithm algorithm) {
        this.algorithm = algorithm == null ? null : algorithm.algorithmName();
>>>>>>> 6848bc6 (Add #205 phase 1 algorithm enums for builder APIs)
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
     * Sets the cryptographic provider from the built-in provider enum.
     *
     * @param provider provider selection, or {@code null} for JVM default
     * @return this builder
     */
    public VerifierBuilder provider(Bruce.Provider provider) {
        this.provider = provider == null ? "" : provider.providerName();
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
        return SignatureOperations.createVerifierByKey(Map.copyOf(publicKeyMap), algorithm, provider);
    }

    private void validateSingleKeyVerifier() {
        Preconditions.requireNonNull(publicKey, "publicKey");
        Preconditions.requireNonBlank(algorithm, "algorithm");
    }

    private void validateMultiKeyVerifier() {
        Preconditions.requireNonEmpty(publicKeyMap, "publicKeyMap");
        Preconditions.requireNonBlank(algorithm, "algorithm");
    }
}
