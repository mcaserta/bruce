package com.mirkocaserta.bruce.api;

public interface KeyStore {
  java.security.KeyStore with(KeyStoreParam... params);
}
