package com.mirkocaserta.bruce;

/**
 * Feature-focused facade for signature and verification operations.
 */
public final class Signatures {

    private Signatures() {
        // utility class
    }

    /**
     * Creates a signer builder.
     *
     * @return a new {@link SignerBuilder}
     */
    public static SignerBuilder signerBuilder() {
        return new SignerBuilder();
    }

    /**
     * Creates a verifier builder.
     *
     * @return a new {@link VerifierBuilder}
     */
    public static VerifierBuilder verifierBuilder() {
        return new VerifierBuilder();
    }
}
