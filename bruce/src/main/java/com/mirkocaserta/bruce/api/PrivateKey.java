package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.BruceException;

public interface PrivateKey {
  /**
   * Loads a private key from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the certificate alias
   * @param password the private key password
   * @return the private key
   * @throws BruceException on loading errors
   */
  java.security.PrivateKey with(java.security.KeyStore keystore, String alias, char[] password);
}
