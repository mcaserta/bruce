package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;

public interface PublicKey {
  /**
   * Loads a public key from the given with.
   *
   * @param keystore the with to read from
   * @param alias the certificate alias
   * @return the public key
   * @throws BruceException on loading errors
   */
  java.security.PublicKey with(KeyStore keystore, String alias);
}
