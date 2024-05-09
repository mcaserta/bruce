package com.mirkocaserta.bruce;

import java.security.KeyStore;

public interface Keystore {
  KeyStore with();

  KeyStore with(String type);

  KeyStore with(String location, char[] password);

  KeyStore with(String location, char[] password, String type);

  KeyStore with(String location, char[] password, String type, String provider);
}
