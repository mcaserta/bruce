package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.impl.digest.DigestOperations;

/**
 * Builder for creating {@link Digester} instances.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class DigestBuilder {

    private String algorithm;
    private String provider = "";

    DigestBuilder() {}

    /** Sets the digest algorithm (e.g., {@code "SHA-256"}, {@code "MD5"}). */
    public DigestBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /** Sets the cryptographic provider (e.g., {@code "BC"} for Bouncy Castle). */
    public DigestBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    public Digester build() {
        if (algorithm == null) throw new BruceException("algorithm is required for digester");
        return DigestOperations.createDigester(algorithm, provider);
    }
}
