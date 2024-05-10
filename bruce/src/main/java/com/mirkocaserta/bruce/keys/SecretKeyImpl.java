package com.mirkocaserta.bruce.keys;

import com.mirkocaserta.bruce.BruceException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

public final class SecretKeyImpl implements com.mirkocaserta.bruce.api.SecretKey {
  @Override
  public Key with(
      final java.security.KeyStore keystore, final String alias, final char[] password) {
    try {
      final var key = keystore.getKey(alias, password);

      if (key == null) {
        throw new BruceException(String.format("no such secret key with alias: %s", alias));
      }

      return key;
    } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
      throw new BruceException(String.format("error loading secret key with alias: %s", alias), e);
    }
  }
}
