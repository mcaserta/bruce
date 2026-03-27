package com.mirkocaserta.bruce;

/**
 * Type-safe enumeration of standard JCA asymmetric cipher transformation strings.
 *
 * <p>Use these constants with {@link CipherBuilder#algorithm(AsymmetricAlgorithm)}
 * instead of raw strings to get compile-time safety and IDE auto-completion:
 *
 * <pre>{@code
 * AsymmetricEncryptor encryptor = Bruce.cipherBuilder()
 *     .key(publicKey)
 *     .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
 *     .buildAsymmetricEncryptor();
 * }</pre>
 *
 * <p>All transformation names are defined by the
 * <a href="https://docs.oracle.com/en/java/docs/specs/security/standard-names.html#cipher-algorithm-names">
 * JCA Standard Algorithm Names</a> specification.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 * @see CipherBuilder#algorithm(AsymmetricAlgorithm)
 */
public enum AsymmetricAlgorithm implements AlgorithmId {

    // ── RSA ──────────────────────────────────────────────────────────────────

    /**
     * RSA cipher (defaults to ECB mode with PKCS1 padding on most JVMs).
     * Equivalent to {@link #RSA_ECB_PKCS1} on standard JDK.
     */
    RSA("RSA"),

    /** RSA in ECB mode with PKCS #1 v1.5 padding. Widely supported; adequate for most uses. */
    RSA_ECB_PKCS1("RSA/ECB/PKCS1Padding"),

    /**
     * RSA in ECB mode with OAEP padding using SHA-1 and MGF1.
     * Recommended over PKCS1 for new applications.
     */
    RSA_ECB_OAEP_SHA1_MGF1("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),

    /**
     * RSA in ECB mode with OAEP padding using SHA-256 and MGF1.
     * Recommended for high-security applications.
     */
    RSA_ECB_OAEP_SHA256_MGF1("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),

    /**
     * RSA in ECB mode with OAEP padding using SHA-384 and MGF1.
     */
    RSA_ECB_OAEP_SHA384_MGF1("RSA/ECB/OAEPWithSHA-384AndMGF1Padding"),

    /**
     * RSA in ECB mode with OAEP padding using SHA-512 and MGF1.
     */
    RSA_ECB_OAEP_SHA512_MGF1("RSA/ECB/OAEPWithSHA-512AndMGF1Padding"),

    /** RSA in ECB mode without padding. Rarely used directly; prefer a padded variant. */
    RSA_ECB_NO_PADDING("RSA/ECB/NoPadding");

    private final String algorithmName;

    AsymmetricAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the JCA cipher transformation string.
     *
     * @return JCA transformation (e.g., {@code "RSA/ECB/PKCS1Padding"})
     */
    @Override
    public String algorithmName() {
        return algorithmName;
    }
}
