package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.BruceException;
import java.security.Key;

public interface SecretKey {
  /**
   * Loads a secret key from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the secret key alias
   * @param password the secret key password
   * @return the secret key
   * @throws BruceException on loading errors
   */
  Key with(java.security.KeyStore keystore, String alias, char[] password);
}
