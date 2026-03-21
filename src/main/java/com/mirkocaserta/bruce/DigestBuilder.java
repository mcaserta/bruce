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
     * Builds a digester.
     *
     * @return configured {@link Digester}
     */
    public Digester build() {
        Preconditions.requireNonBlank(algorithm, "algorithm");
        return DigestOperations.createDigester(algorithm, provider);
    }
}
