package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.util.Preconditions;
import com.mirkocaserta.bruce.impl.signature.SignatureOperations;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.SignerByKey;

import java.security.PrivateKey;
import java.util.Map;

/**
 * Builder for creating {@link Signer} and {@link SignerByKey} instances.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class SignerBuilder {

    private PrivateKey privateKey;
    private Map<String, PrivateKey> privateKeyMap;
    private String algorithm;
    private String provider = "";

    SignerBuilder() {}

    /**
     * Sets the private key for signing.
     *
     * @param privateKey private key used to sign
     * @return this builder
     */
    public SignerBuilder key(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /**
     * Sets a map of private keys for runtime key selection.
     *
     * @param privateKeyMap map of key-id to private key
     * @return this builder
     */
    public SignerBuilder keys(Map<String, PrivateKey> privateKeyMap) {
        this.privateKeyMap = privateKeyMap;
        return this;
    }

    /**
     * Sets the signing algorithm (e.g., {@code "SHA256withRSA"}).
     *
     * @param algorithm signature algorithm
     * @return this builder
     */
    public SignerBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the signing algorithm using the type-safe {@link SignatureAlgorithm} enum.
     *
     * <pre>{@code
     * Signer signer = Bruce.signerBuilder()
     *     .key(privateKey)
     *     .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
     *     .build();
     * }</pre>
     *
     * @param algorithm signature algorithm constant; must not be {@code null}
     * @return this builder
     */
    public SignerBuilder algorithm(SignatureAlgorithm algorithm) {
        Preconditions.requireNonNull(algorithm, "algorithm");
        this.algorithm = algorithm.algorithmName();
        return this;
    }

    /**
     * Sets the cryptographic provider (e.g., {@code "BC"} for Bouncy Castle).
     *
     * @param provider provider name, or {@code null} / empty for JVM default
     * @return this builder
     */
    public SignerBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    /**
     * Sets the cryptographic provider from the built-in provider enum.
     *
     * @param provider provider selection, or {@code null} for JVM default
     * @return this builder
     */
    public SignerBuilder provider(Bruce.Provider provider) {
        this.provider = provider == null ? "" : provider.providerName();
        return this;
    }

    /**
     * Builds a signer using a single preconfigured key.
     *
     * @return configured {@link Signer}
     */
    public Signer build() {
        validateSingleKeySigner();
        return SignatureOperations.createSigner(privateKey, algorithm, provider);
    }

    /**
     * Builds a signer that selects a key by id at call time.
     *
     * @return configured {@link SignerByKey}
     */
    public SignerByKey buildByKey() {
        validateMultiKeySigner();
        return SignatureOperations.createSignerByKey(Map.copyOf(privateKeyMap), algorithm, provider);
    }

    private void validateSingleKeySigner() {
        Preconditions.requireNonNull(privateKey, "privateKey");
        Preconditions.requireNonBlank(algorithm, "algorithm");
    }

    private void validateMultiKeySigner() {
        Preconditions.requireNonEmpty(privateKeyMap, "privateKeyMap");
        Preconditions.requireNonBlank(algorithm, "algorithm");
    }
}
