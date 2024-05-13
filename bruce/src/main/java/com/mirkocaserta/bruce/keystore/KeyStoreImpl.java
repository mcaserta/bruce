package com.mirkocaserta.bruce.keystore;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.api.KeyStore;
import com.mirkocaserta.bruce.api.params.KeyStoreParam;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Optional;

public final class KeyStoreImpl implements KeyStore {
  /** The default keystore format/type. */
  private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

  private static final String BLANK = "";

  @Override
  public java.security.KeyStore with(KeyStoreParam... paramsArray) {
    final var params = KeyStoreParams.of(paramsArray);

    if (params.isUseSystemProperties() && params.isTypeSet()) {
      return with(params.type());
    } else if (params.isUseSystemProperties()) {
      return with();
    } else if (params.isAllParamsSet()) {
      return with(params.location(), params.password(), params.type(), params.provider());
    } else if (params.isLocationPasswordAndTypeSet()) {
      return with(params.location(), params.password(), params.type());
    } else if (params.isLocationAndPasswordSet()) {
      return with(params.location(), params.password());
    } else if (params.isTypeSet()) {
      return with(params.type());
    }

    return with();
  }

  private java.security.KeyStore with() {
    return with(DEFAULT_KEYSTORE_TYPE);
  }

  private java.security.KeyStore with(final String type) {
    return with(
        System.getProperty("javax.net.ssl.keyStore"),
        Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"))
            .orElse(BLANK)
            .toCharArray(),
        type);
  }

  private java.security.KeyStore with(final String location, final char[] password) {
    return with(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
  }

  private java.security.KeyStore with(
      final String location, final char[] password, final String type) {
    return with(location, password, type, BLANK);
  }

  private java.security.KeyStore with(
      final String location, final char[] password, final String type, final String provider) {
    if (location == null || location.isBlank()) {
      throw new BruceException("please provide a valid keystore location");
    }

    try {
      final var keyStore =
          provider == null || provider.isBlank()
              ? java.security.KeyStore.getInstance(type)
              : java.security.KeyStore.getInstance(type, provider);
      final InputStream inputStream;
      if (location.startsWith("classpath:")) {
        inputStream = Bruce.class.getResourceAsStream(location.replaceFirst("classpath:", BLANK));
      } else if (location.matches("^https*://.*$")) {
        inputStream = new URL(location).openConnection().getInputStream();
      } else {
        inputStream = Files.newInputStream(Path.of(location.replaceFirst("file:", BLANK)));
      }
      keyStore.load(inputStream, password);
      return keyStore;
    } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
      throw new BruceException(String.format("error loading keystore: location=%s", location), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(
          String.format("error loading keystore, no such provider: provider=%s", provider), e);
    } catch (Exception e) {
      throw new BruceException("error loading keystore", e);
    }
  }
}
