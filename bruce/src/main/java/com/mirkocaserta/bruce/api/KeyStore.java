package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.BruceException;

public interface KeyStore {
  /**
   * Returns the default keystore using configuration from the following system properties:
   *
   * <ul>
   *   <li><code>javax.net.ssl.keyStore</code>
   *   <li><code>javax.net.ssl.keyStorePassword</code>
   * </ul>
   *
   * <p>The keystore location supports the following protocols:
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
   * <p>The default keystore type is <code>PKCS12</code>.
   *
   * @return the default keystore
   * @throws BruceException on loading errors
   */
  java.security.KeyStore with();

  /**
   * Returns the default keystore using configuration from the following system properties:
   *
   * <ul>
   *   <li><code>javax.net.ssl.keyStore</code>
   *   <li><code>javax.net.ssl.keyStorePassword</code>
   * </ul>
   *
   * <p>The keystore location supports the following protocols:
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
   * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @return the default keystore
   * @throws BruceException on loading errors
   */
  java.security.KeyStore with(String type);

  /**
   * Returns a key store. The default keystore type is <code>PKCS12</code>.
   *
   * @param location the keystore location. The following protocols are supported:
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
  java.security.KeyStore with(String location, char[] password);

  /**
   * Returns a key store.
   *
   * @param location the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @return a key store
   * @throws BruceException on loading errors
   */
  java.security.KeyStore with(String location, char[] password, String type);

  /**
   * Returns a key store.
   *
   * @param location the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a key store
   * @throws BruceException on loading errors
   */
  java.security.KeyStore with(String location, char[] password, String type, String provider);
}
