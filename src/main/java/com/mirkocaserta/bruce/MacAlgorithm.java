package com.mirkocaserta.bruce;

/**
 * Type-safe enumeration of standard JCA HMAC (Hash-based Message Authentication
 * Code) algorithm names.
 *
 * <p>Use these constants with {@link MacBuilder#algorithm(MacAlgorithm)}
 * instead of raw strings to get compile-time safety and IDE auto-completion:
 *
 * <pre>{@code
 * Mac mac = Bruce.macBuilder()
 *     .key(secretKey)
 *     .algorithm(MacAlgorithm.HMAC_SHA_256)
 *     .build();
 * }</pre>
 *
 * <p>All algorithm names are defined by the
 * <a href="https://docs.oracle.com/en/java/docs/specs/security/standard-names.html#mac-algorithms">
 * JCA Standard Algorithm Names</a> specification.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 * @see MacBuilder#algorithm(MacAlgorithm)
 */
public enum MacAlgorithm implements AlgorithmId {

    /** HMAC using MD5 (128-bit). Not recommended for security-sensitive uses. */
    HMAC_MD5("HmacMD5"),

    /** HMAC using SHA-1 (160-bit). Not recommended for new applications. */
    HMAC_SHA_1("HmacSHA1"),

    /** HMAC using SHA-224 (224-bit). */
    HMAC_SHA_224("HmacSHA224"),

    /** HMAC using SHA-256 (256-bit). Recommended for general use. */
    HMAC_SHA_256("HmacSHA256"),

    /** HMAC using SHA-384 (384-bit). */
    HMAC_SHA_384("HmacSHA384"),

    /** HMAC using SHA-512 (512-bit). */
    HMAC_SHA_512("HmacSHA512"),

    /** HMAC using SHA-512/224 (224-bit). */
    HMAC_SHA_512_224("HmacSHA512/224"),

    /** HMAC using SHA-512/256 (256-bit). */
    HMAC_SHA_512_256("HmacSHA512/256"),

    /** HMAC using SHA3-224 (224-bit, SHA-3 family). */
    HMAC_SHA3_224("HmacSHA3-224"),

    /** HMAC using SHA3-256 (256-bit, SHA-3 family). */
    HMAC_SHA3_256("HmacSHA3-256"),

    /** HMAC using SHA3-384 (384-bit, SHA-3 family). */
    HMAC_SHA3_384("HmacSHA3-384"),

    /** HMAC using SHA3-512 (512-bit, SHA-3 family). */
    HMAC_SHA3_512("HmacSHA3-512");

    private final String algorithmName;

    MacAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the JCA algorithm name for this MAC algorithm.
     *
     * @return JCA algorithm name (e.g., {@code "HmacSHA256"})
     */
    @Override
    public String algorithmName() {
        return algorithmName;
    }
}
