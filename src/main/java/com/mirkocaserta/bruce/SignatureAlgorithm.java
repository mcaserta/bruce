package com.mirkocaserta.bruce;

/**
 * Type-safe enumeration of standard JCA digital-signature algorithm names.
 *
 * <p>Use these constants with {@link SignerBuilder#algorithm(SignatureAlgorithm)}
 * and {@link VerifierBuilder#algorithm(SignatureAlgorithm)} instead of raw
 * strings to get compile-time safety and IDE auto-completion:
 *
 * <pre>{@code
 * Signer signer = Bruce.signerBuilder()
 *     .key(privateKey)
 *     .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
 *     .build();
 *
 * Verifier verifier = Bruce.verifierBuilder()
 *     .key(publicKey)
 *     .algorithm(SignatureAlgorithm.SHA256_WITH_RSA)
 *     .build();
 * }</pre>
 *
 * <p>All algorithm names are defined by the
 * <a href="https://docs.oracle.com/en/java/docs/specs/security/standard-names.html#signature-algorithms">
 * JCA Standard Algorithm Names</a> specification.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 * @see SignerBuilder#algorithm(SignatureAlgorithm)
 * @see VerifierBuilder#algorithm(SignatureAlgorithm)
 */
public enum SignatureAlgorithm implements AlgorithmId {

    // ── RSA signatures ──────────────────────────────────────────────────────

    /** MD5 with RSA. Not recommended for new applications. */
    MD5_WITH_RSA("MD5withRSA"),

    /** SHA-1 with RSA. Not recommended for new applications. */
    SHA1_WITH_RSA("SHA1withRSA"),

    /** SHA-224 with RSA. */
    SHA224_WITH_RSA("SHA224withRSA"),

    /** SHA-256 with RSA. Recommended for general use. */
    SHA256_WITH_RSA("SHA256withRSA"),

    /** SHA-384 with RSA. */
    SHA384_WITH_RSA("SHA384withRSA"),

    /** SHA-512 with RSA. */
    SHA512_WITH_RSA("SHA512withRSA"),

    /** SHA-512/224 with RSA. */
    SHA512_224_WITH_RSA("SHA512/224withRSA"),

    /** SHA-512/256 with RSA. */
    SHA512_256_WITH_RSA("SHA512/256withRSA"),

    /** SHA3-256 with RSA. */
    SHA3_256_WITH_RSA("SHA3-256withRSA"),

    /** SHA3-384 with RSA. */
    SHA3_384_WITH_RSA("SHA3-384withRSA"),

    /** SHA3-512 with RSA. */
    SHA3_512_WITH_RSA("SHA3-512withRSA"),

    /** RSA Signature Scheme with Appendix - Probabilistic Signature Scheme (RSASSA-PSS). */
    RSASSA_PSS("RSASSA-PSS"),

    // ── DSA signatures ──────────────────────────────────────────────────────

    /** SHA-1 with DSA. Not recommended for new applications. */
    SHA1_WITH_DSA("SHA1withDSA"),

    /** SHA-224 with DSA. */
    SHA224_WITH_DSA("SHA224withDSA"),

    /** SHA-256 with DSA. */
    SHA256_WITH_DSA("SHA256withDSA"),

    /** SHA-384 with DSA. */
    SHA384_WITH_DSA("SHA384withDSA"),

    /** SHA-512 with DSA. */
    SHA512_WITH_DSA("SHA512withDSA"),

    /** SHA3-224 with DSA. */
    SHA3_224_WITH_DSA("SHA3-224withDSA"),

    /** SHA3-256 with DSA. */
    SHA3_256_WITH_DSA("SHA3-256withDSA"),

    /** SHA3-384 with DSA. */
    SHA3_384_WITH_DSA("SHA3-384withDSA"),

    /** SHA3-512 with DSA. */
    SHA3_512_WITH_DSA("SHA3-512withDSA"),

    // ── ECDSA signatures ────────────────────────────────────────────────────

    /** SHA-1 with ECDSA. Not recommended for new applications. */
    SHA1_WITH_ECDSA("SHA1withECDSA"),

    /** SHA-224 with ECDSA. */
    SHA224_WITH_ECDSA("SHA224withECDSA"),

    /** SHA-256 with ECDSA. Recommended for general use with EC keys. */
    SHA256_WITH_ECDSA("SHA256withECDSA"),

    /** SHA-384 with ECDSA. */
    SHA384_WITH_ECDSA("SHA384withECDSA"),

    /** SHA-512 with ECDSA. */
    SHA512_WITH_ECDSA("SHA512withECDSA"),

    /** SHA3-224 with ECDSA. */
    SHA3_224_WITH_ECDSA("SHA3-224withECDSA"),

    /** SHA3-256 with ECDSA. */
    SHA3_256_WITH_ECDSA("SHA3-256withECDSA"),

    /** SHA3-384 with ECDSA. */
    SHA3_384_WITH_ECDSA("SHA3-384withECDSA"),

    /** SHA3-512 with ECDSA. */
    SHA3_512_WITH_ECDSA("SHA3-512withECDSA");

    private final String algorithmName;

    SignatureAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the JCA algorithm name for this signature algorithm.
     *
     * @return JCA algorithm name (e.g., {@code "SHA256withRSA"})
     */
    @Override
    public String algorithmName() {
        return algorithmName;
    }
}
