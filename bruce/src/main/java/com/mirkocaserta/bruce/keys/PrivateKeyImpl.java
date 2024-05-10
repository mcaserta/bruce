package com.mirkocaserta.bruce.keys;

import com.mirkocaserta.bruce.BruceException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;

public final class PrivateKeyImpl implements com.mirkocaserta.bruce.api.PrivateKey {
  @Override
  public PrivateKey with(
      final java.security.KeyStore keystore, final String alias, final char[] password) {
    try {
      final var privateKeyEntry =
          (java.security.KeyStore.PrivateKeyEntry)
              keystore.getEntry(alias, new java.security.KeyStore.PasswordProtection(password));

      if (privateKeyEntry == null) {
        throw new BruceException(String.format("no such private key with alias: %s", alias));
      }

      return privateKeyEntry.getPrivateKey();
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
      throw new BruceException(String.format("error loading private key with alias: %s", alias), e);
    }
  }
}
