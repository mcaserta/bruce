package com.mirkocaserta.bruce.keystore;

import com.mirkocaserta.bruce.api.params.KeyStoreParam;

public final class KeyStoreParams {
  private String type = "PKCS12";
  private String location;
  private char[] password;
  private String provider;

  public static KeyStoreParams of(final KeyStoreParam... params) {
    final var prms = new KeyStoreParams();

    if (params == null) {
      return prms;
    }

    for (var param : params) {
      if (param != null) {
        switch (param.type()) {
          case TYPE -> prms.setType(param.value());
          case LOCATION -> prms.setLocation(param.value());
          case PASSWORD -> prms.setPassword(param.password());
          case PROVIDER -> prms.setProvider(param.value());
        }
      }
    }

    return prms;
  }

  private void setType(String type) {
    this.type = type;
  }

  private void setLocation(String location) {
    this.location = location;
  }

  private void setPassword(char[] password) {
    this.password = password;
  }

  private void setProvider(String provider) {
    this.provider = provider;
  }

  public String type() {
    return type;
  }

  public String location() {
    return location;
  }

  public char[] password() {
    return password;
  }

  public String provider() {
    return provider;
  }

  public boolean isUseSystemProperties() {
    return location != null && location.equals("SYSTEM_PROPERTIES");
  }

  public boolean isAllParamsSet() {
    return type != null && location != null && password != null && provider != null;
  }

  public boolean isLocationPasswordAndTypeSet() {
    return type != null && location != null && password != null;
  }

  public boolean isLocationAndPasswordSet() {
    return location != null && password != null;
  }

  public boolean isTypeSet() {
    return type != null;
  }
}
