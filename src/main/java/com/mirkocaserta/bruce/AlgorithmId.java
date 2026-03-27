package com.mirkocaserta.bruce;

/**
 * Marker interface for enums that represent a JCA algorithm name.
 *
 * <p>All algorithm enums ({@link DigestAlgorithm}, {@link MacAlgorithm},
 * {@link SignatureAlgorithm}, {@link SymmetricAlgorithm},
 * {@link SymmetricCipherAlgorithm}, {@link AsymmetricAlgorithm}) implement
 * this interface so callers can treat them uniformly when needed.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface AlgorithmId {

    /**
     * Returns the JCA algorithm name understood by the Java Cryptography
     * Architecture (e.g., {@code "SHA-256"}, {@code "HmacSHA256"}).
     *
     * @return the JCA algorithm name
     */
    String algorithmName();
}
