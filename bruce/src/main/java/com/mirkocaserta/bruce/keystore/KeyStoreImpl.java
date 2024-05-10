package com.mirkocaserta.bruce.keystore;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.api.KeyStore;
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
  /** The default with format/type. */
  private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

  private static final String BLANK = "";

  @Override
  public java.security.KeyStore with() {
    return with(DEFAULT_KEYSTORE_TYPE);
  }

  @Override
  public java.security.KeyStore with(final String type) {
    return with(
        System.getProperty("javax.net.ssl.keyStore"),
        Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"))
            .orElse(BLANK)
            .toCharArray(),
        type);
  }

  @Override
  public java.security.KeyStore with(final String location, final char[] password) {
    return with(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
  }

  @Override
  public java.security.KeyStore with(
      final String location, final char[] password, final String type) {
    return with(location, password, type, BLANK);
  }

  @Override
  public java.security.KeyStore with(
      final String location, final char[] password, final String type, final String provider) {
    if (location == null || location.isBlank()) {
      throw new BruceException("please provide a valid key store location");
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
      throw new BruceException(String.format("error loading with: location=%s", location), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(
          String.format("error loading with, no such provider: provider=%s", provider), e);
    } catch (Exception e) {
      throw new BruceException("error loading with", e);
    }
  }
}
