package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.impl.digest.DigestOperations;
import com.mirkocaserta.bruce.impl.util.Preconditions;

/**
 * Builder for creating {@link Digester} instances.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class DigestBuilder {

    private String algorithm;
    private String provider = "";

    DigestBuilder() {}

    /**
     * Sets the digest algorithm (e.g., {@code "SHA-256"}, {@code "MD5"}).
     *
     * @param algorithm digest algorithm
     * @return this builder
     */
    public DigestBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the digest algorithm using the type-safe {@link DigestAlgorithm} enum.
     *
     * <pre>{@code
     * Digester digester = Bruce.digestBuilder()
     *     .algorithm(DigestAlgorithm.SHA_256)
     *     .build();
     * }</pre>
     *
     * @param algorithm digest algorithm constant; must not be {@code null}
     * @return this builder
     */
    public DigestBuilder algorithm(DigestAlgorithm algorithm) {
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
    public DigestBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    /**
     * Sets the cryptographic provider from the built-in provider enum.
     *
     * @param provider provider selection, or {@code null} for JVM default
     * @return this builder
     */
    public DigestBuilder provider(Bruce.Provider provider) {
        this.provider = provider == null ? "" : provider.providerName();
        return this;
    }

    /**
     * Builds a digester.
     *
     * @return configured {@link Digester}
     */
    public Digester build() {
        Preconditions.requireNonBlank(algorithm, "algorithm");
        return DigestOperations.createDigester(algorithm, provider);
    }
}
