package com.mirkocaserta.bruce.certificate;

import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

public final class CertificateImpl implements com.mirkocaserta.bruce.api.Certificate {
  @Override
  public Certificate with(final KeyStore keystore, final String alias) {
    try {
      final var certificate = keystore.getCertificate(alias);

      if (certificate == null) {
        throw new BruceException(String.format("certificate not found for alias: %s", alias));
      }

      return certificate;
    } catch (KeyStoreException e) {
      throw new BruceException(String.format("error loading certificate with alias: %s", alias), e);
    }
  }
}
