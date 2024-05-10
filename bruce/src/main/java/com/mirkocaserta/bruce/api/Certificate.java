package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;

public interface Certificate {
  /**
   * Loads a certificate from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the certificate alias
   * @return the certificate
   * @throws BruceException on loading errors
   */
  java.security.cert.Certificate with(KeyStore keystore, String alias);
}
