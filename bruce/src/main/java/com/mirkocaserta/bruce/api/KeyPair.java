package com.mirkocaserta.bruce.api;

import java.security.SecureRandom;

public interface KeyPair {
  /**
   * Generates a key pair.
   *
   * @param algorithm the key algorithm
   * @param keySize the key size
   * @return the key pair
   */
  java.security.KeyPair with(String algorithm, int keySize);

  /**
   * Generates a key pair.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param keySize the key size
   * @return the key pair
   */
  java.security.KeyPair with(String algorithm, String provider, int keySize);

  /**
   * Generates a key pair with the specified random number generator.
   *
   * @param algorithm the key algorithm
   * @param keySize the key size
   * @param random the random number generator
   * @return the key pair
   */
  java.security.KeyPair with(String algorithm, int keySize, SecureRandom random);

  /**
   * Generates a key pair with the specified provider and random number generator.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param keySize the key size
   * @param random the random number generator
   * @return the key pair
   */
  java.security.KeyPair with(String algorithm, String provider, int keySize, SecureRandom random);
}
