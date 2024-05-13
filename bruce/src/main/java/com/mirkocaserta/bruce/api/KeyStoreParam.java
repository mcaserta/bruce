package com.mirkocaserta.bruce.api;

public final class KeyStoreParam {
  private final Type type;
  private final String value;
  private final char[] password;

  private KeyStoreParam(final Type type, final String value, final char[] password) {
    this.type = type;
    this.value = value;
    this.password = password;
  }

  /**
   * Sets the keystore type.
   *
   * @param value the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   */
  public static KeyStoreParam type(final String value) {
    return new KeyStoreParam(Type.TYPE, value, null);
  }

  /**
   * Sets the keystore location.
   *
   * @param value the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   */
  public static KeyStoreParam location(final String value) {
    return new KeyStoreParam(Type.LOCATION, value, null);
  }

  /**
   * Sets the keystore password.
   *
   * @param value the keystore password
   */
  public static KeyStoreParam password(final char[] value) {
    return new KeyStoreParam(Type.PASSWORD, null, value);
  }

  /**
   * Sets the keystore provider
   *
   * @param value the provider (hint: Bouncy Castle is <code>BC</code>)
   */
  public static KeyStoreParam provider(final String value) {
    return new KeyStoreParam(Type.PROVIDER, value, null);
  }

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
   */
  public static KeyStoreParam useSystemProps() {
    return new KeyStoreParam(Type.LOCATION, "SYSTEM_PROPERTIES", null);
  }

  public Type type() {
    return type;
  }

  public String value() {
    return value;
  }

  public char[] password() {
    return password;
  }

  public enum Type {
    TYPE,
    LOCATION,
    PASSWORD,
    PROVIDER
  }
}
