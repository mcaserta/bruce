package com.mirkocaserta.bruce;

/**
 * Type-safe enumeration of standard JCA symmetric cipher <em>transformation</em>
 * strings (algorithm/mode/padding).
 *
 * <p>These values are used as the {@code cipherAlgorithm} parameter in
 * {@link CipherBuilder}. The matching key algorithm is represented by
 * {@link SymmetricAlgorithm}.
 *
 * <p>Typical usage:
 *
 * <pre>{@code
 * SymmetricEncryptor encryptor = Bruce.cipherBuilder()
 *     .key(keyBytes)
 *     .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
 *     .buildSymmetricEncryptor();
 * }</pre>
 *
 * <p>All transformation names are defined by the
 * <a href="https://docs.oracle.com/en/java/docs/specs/security/standard-names.html#cipher-algorithm-names">
 * JCA Standard Algorithm Names</a> specification.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 * @see CipherBuilder#algorithm(SymmetricCipherAlgorithm)
 * @see CipherBuilder#algorithms(SymmetricAlgorithm, SymmetricCipherAlgorithm)
 * @see SymmetricAlgorithm
 */
public enum SymmetricCipherAlgorithm implements AlgorithmId {

    // ── AES ─────────────────────────────────────────────────────────────────

    /** AES in CBC mode with PKCS #5 / PKCS #7 padding. Most widely used AES mode. */
    AES_CBC_PKCS5("AES/CBC/PKCS5Padding"),

    /** AES in CBC mode without padding. Requires plaintext length to be a multiple of 16. */
    AES_CBC_NO_PADDING("AES/CBC/NoPadding"),

    /** AES in CTR (counter) mode without padding. Stream-cipher-like behaviour. */
    AES_CTR_NO_PADDING("AES/CTR/NoPadding"),

    /** AES in ECB mode with PKCS #5 padding. Not recommended; does not hide patterns. */
    AES_ECB_PKCS5("AES/ECB/PKCS5Padding"),

    /** AES in ECB mode without padding. Not recommended; does not hide patterns. */
    AES_ECB_NO_PADDING("AES/ECB/NoPadding"),

    /**
     * AES in GCM (Galois/Counter Mode) without padding. Provides authenticated
     * encryption; recommended when integrity is also required.
     */
    AES_GCM_NO_PADDING("AES/GCM/NoPadding"),

    // ── DES ─────────────────────────────────────────────────────────────────

    /** DES in CBC mode with PKCS #5 padding. Not recommended for new applications. */
    DES_CBC_PKCS5("DES/CBC/PKCS5Padding"),

    /** DES in ECB mode with PKCS #5 padding. Not recommended for new applications. */
    DES_ECB_PKCS5("DES/ECB/PKCS5Padding"),

    // ── DESede (3DES) ────────────────────────────────────────────────────────

    /** Triple DES in CBC mode with PKCS #5 padding. Deprecated; prefer AES. */
    DESEDE_CBC_PKCS5("DESede/CBC/PKCS5Padding"),

    /** Triple DES in ECB mode with PKCS #5 padding. Deprecated; prefer AES. */
    DESEDE_ECB_PKCS5("DESede/ECB/PKCS5Padding"),

    // ── Blowfish ─────────────────────────────────────────────────────────────

    /** Blowfish in CBC mode with PKCS #5 padding. */
    BLOWFISH_CBC_PKCS5("Blowfish/CBC/PKCS5Padding"),

    /** Blowfish in ECB mode with PKCS #5 padding. */
    BLOWFISH_ECB_PKCS5("Blowfish/ECB/PKCS5Padding");

    private final String algorithmName;

    SymmetricCipherAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the JCA cipher transformation string.
     *
     * @return JCA transformation (e.g., {@code "AES/CBC/PKCS5Padding"})
     */
    @Override
    public String algorithmName() {
        return algorithmName;
    }
}
