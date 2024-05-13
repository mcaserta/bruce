package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.api.params.KeyStoreParam;

public interface KeyStore {
  java.security.KeyStore with(KeyStoreParam... params);
}
