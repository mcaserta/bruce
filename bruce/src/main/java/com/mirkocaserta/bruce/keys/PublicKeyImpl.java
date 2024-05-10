package com.mirkocaserta.bruce.keys;

import com.mirkocaserta.bruce.Bruce;
import java.security.KeyStore;
import java.security.PublicKey;

public final class PublicKeyImpl implements com.mirkocaserta.bruce.api.PublicKey {
  @Override
  public PublicKey with(final KeyStore keystore, final String alias) {
    return Bruce.certificate.with(keystore, alias).getPublicKey();
  }
}
