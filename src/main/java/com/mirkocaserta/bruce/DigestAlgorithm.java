package com.mirkocaserta.bruce;

/**
 * Type-safe enumeration of standard JCA message-digest algorithm names.
 *
 * <p>Use these constants with {@link DigestBuilder#algorithm(DigestAlgorithm)}
 * instead of raw strings to get compile-time safety and IDE auto-completion:
 *
 * <pre>{@code
 * Digester digester = Bruce.digestBuilder()
 *     .algorithm(DigestAlgorithm.SHA_256)
 *     .build();
 * }</pre>
 *
 * <p>All algorithm names are defined by the
 * <a href="https://docs.oracle.com/en/java/docs/specs/security/standard-names.html#messagedigest-algorithms">
 * JCA Standard Algorithm Names</a> specification.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 * @see DigestBuilder#algorithm(DigestAlgorithm)
 */
public enum DigestAlgorithm implements AlgorithmId {

    /** MD5 message digest (128-bit). Not recommended for security-sensitive uses. */
    MD5("MD5"),

    /** SHA-1 message digest (160-bit). Not recommended for security-sensitive uses. */
    SHA_1("SHA-1"),

    /** SHA-224 message digest (224-bit, SHA-2 family). */
    SHA_224("SHA-224"),

    /** SHA-256 message digest (256-bit, SHA-2 family). Recommended for general use. */
    SHA_256("SHA-256"),

    /** SHA-384 message digest (384-bit, SHA-2 family). */
    SHA_384("SHA-384"),

    /** SHA-512 message digest (512-bit, SHA-2 family). */
    SHA_512("SHA-512"),

    /** SHA-512/224 truncated message digest (224-bit, SHA-2 family). */
    SHA_512_224("SHA-512/224"),

    /** SHA-512/256 truncated message digest (256-bit, SHA-2 family). */
    SHA_512_256("SHA-512/256"),

    /** SHA3-224 message digest (224-bit, SHA-3 family). */
    SHA3_224("SHA3-224"),

    /** SHA3-256 message digest (256-bit, SHA-3 family). */
    SHA3_256("SHA3-256"),

    /** SHA3-384 message digest (384-bit, SHA-3 family). */
    SHA3_384("SHA3-384"),

    /** SHA3-512 message digest (512-bit, SHA-3 family). */
    SHA3_512("SHA3-512");

    private final String algorithmName;

    DigestAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the JCA algorithm name for this digest algorithm.
     *
     * @return JCA algorithm name (e.g., {@code "SHA-256"})
     */
    @Override
    public String algorithmName() {
        return algorithmName;
    }
}
