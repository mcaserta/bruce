package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for signature and verification operations.
 */
public final class Signatures {

    private Signatures() {
        // utility class
    }

    public static SignerBuilder signerBuilder() {
        return new SignerBuilder();
    }

    public static VerifierBuilder verifierBuilder() {
        return new VerifierBuilder();
    }
}
