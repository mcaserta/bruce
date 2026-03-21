package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.SignerByKey;
import com.mirkocaserta.bruce.impl.signature.SignatureOperations;

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

    /** Sets the private key for signing. */
    public SignerBuilder key(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /** Sets a map of private keys for runtime key selection. */
    public SignerBuilder keys(Map<String, PrivateKey> privateKeyMap) {
        this.privateKeyMap = privateKeyMap;
        return this;
    }

    /** Sets the signing algorithm (e.g., {@code "SHA256withRSA"}). */
    public SignerBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /** Sets the cryptographic provider (e.g., {@code "BC"} for Bouncy Castle). */
    public SignerBuilder provider(String provider) {
        this.provider = provider == null ? "" : provider;
        return this;
    }

    public Signer build() {
        validateSingleKeySigner();
        return SignatureOperations.createSigner(privateKey, algorithm, provider);
    }

    public SignerByKey buildByKey() {
        validateMultiKeySigner();
        return SignatureOperations.createSignerByKey(privateKeyMap, algorithm, provider);
    }

    private void validateSingleKeySigner() {
        if (privateKey == null) throw new BruceException("privateKey is required for single key signer");
        if (algorithm == null) throw new BruceException("algorithm is required for signer");
    }

    private void validateMultiKeySigner() {
        if (privateKeyMap == null || privateKeyMap.isEmpty()) throw new BruceException("privateKeyMap is required for multi-key signer");
        if (algorithm == null) throw new BruceException("algorithm is required for signer");
    }
}
