package com.mirkocaserta.bruce;

/**
 * Type-safe enumeration of standard JCA symmetric <em>key</em> algorithm names.
 *
 * <p>These names identify the underlying key type and are used as the
 * {@code keyAlgorithm} parameter in {@link CipherBuilder}. They are separate
 * from the full cipher transformation (e.g., {@code "AES/CBC/PKCS5Padding"}),
 * which is represented by {@link SymmetricCipherAlgorithm}.
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
 * <p>All algorithm names are defined by the
 * <a href="https://docs.oracle.com/en/java/docs/specs/security/standard-names.html#keygenerator-algorithms">
 * JCA Standard Algorithm Names</a> specification.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 * @see CipherBuilder#keyAlgorithm(SymmetricAlgorithm)
 * @see CipherBuilder#algorithms(SymmetricAlgorithm, SymmetricCipherAlgorithm)
 * @see SymmetricCipherAlgorithm
 */
public enum SymmetricAlgorithm implements AlgorithmId {

    /** Advanced Encryption Standard (AES). Recommended for general symmetric encryption. */
    AES("AES"),

    /** Data Encryption Standard (DES, 56-bit). Not recommended for new applications. */
    DES("DES"),

    /** Triple DES / DES-EDE (112-bit or 168-bit). Deprecated; prefer AES. */
    DESEDE("DESede"),

    /** Blowfish variable-key-length cipher (32–448 bits). */
    BLOWFISH("Blowfish"),

    /** RC2 variable-key-length cipher. Not recommended for new applications. */
    RC2("RC2"),

    /** ARC4 / RC4 stream cipher. Not recommended for new applications. */
    RC4("RC4"),

    /** ChaCha20 stream cipher. Requires JDK 11+ or a provider such as Bouncy Castle. */
    CHACHA20("ChaCha20");

    private final String algorithmName;

    SymmetricAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the JCA key-algorithm name for this symmetric algorithm.
     *
     * @return JCA algorithm name (e.g., {@code "AES"})
     */
    @Override
    public String algorithmName() {
        return algorithmName;
    }
}
