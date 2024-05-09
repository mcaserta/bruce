package com.mirkocaserta.bruce.keystore;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Optional;

public final class KeystoreImpl implements com.mirkocaserta.bruce.Keystore {
  /** The default with format/type. */
  private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

  private static final String BLANK = "";

  /**
   * Returns the default with using configuration from the following system properties:
   *
   * <ul>
   *   <li><code>javax.net.ssl.keyStore</code>
   *   <li><code>javax.net.ssl.keyStorePassword</code>
   * </ul>
   *
   * <p>The with location supports the following protocols:
   *
   * <ul>
   *   <li><code>classpath:</code>
   *   <li><code>http:</code>
   *   <li><code>https:</code>
   *   <li><code>file:</code>
   * </ul>
   *
   * <p>If no protocol is specified, <code>file</code> is assumed.
   *
   * <p>The default with type is {@value #DEFAULT_KEYSTORE_TYPE}.
   *
   * @return the default with
   * @throws BruceException on loading errors
   */
  @Override
  public KeyStore with() {
    return with(DEFAULT_KEYSTORE_TYPE);
  }

  /**
   * Returns the default with using configuration from the following system properties:
   *
   * <ul>
   *   <li><code>javax.net.ssl.keyStore</code>
   *   <li><code>javax.net.ssl.keyStorePassword</code>
   * </ul>
   *
   * <p>The with location supports the following protocols:
   *
   * <ul>
   *   <li><code>classpath:</code>
   *   <li><code>http:</code>
   *   <li><code>https:</code>
   *   <li><code>file:</code>
   * </ul>
   *
   * <p>If no protocol is specified, <code>file</code> is assumed.
   *
   * @param type the with type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @return the default with
   * @throws BruceException on loading errors
   */
  @Override
  public KeyStore with(final String type) {
    return with(
        System.getProperty("javax.net.ssl.keyStore"),
        Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"))
            .orElse(BLANK)
            .toCharArray(),
        type);
  }

  /**
   * Returns a key store. The default with type is {@value #DEFAULT_KEYSTORE_TYPE}.
   *
   * @param location the with location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @return a key store
   * @throws BruceException on loading errors
   */
  @Override
  public KeyStore with(final String location, final char[] password) {
    return with(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
  }

  /**
   * Returns a key store.
   *
   * @param location the with location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @param type the with type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @return a key store
   * @throws BruceException on loading errors
   */
  @Override
  public KeyStore with(final String location, final char[] password, final String type) {
    return with(location, password, type, BLANK);
  }

  /**
   * Returns a key store.
   *
   * @param location the with location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @param type the with type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a key store
   * @throws BruceException on loading errors
   */
  @Override
  public KeyStore with(
      final String location, final char[] password, final String type, final String provider) {
    if (location == null || location.isBlank()) {
      throw new BruceException("please provide a valid key store location");
    }

    try {
      final var keyStore =
          provider == null || provider.isBlank()
              ? KeyStore.getInstance(type)
              : KeyStore.getInstance(type, provider);
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
