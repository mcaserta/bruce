package com.mirkocaserta.bruce.api.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.ANNOTATION_TYPE)
public @interface KeyStore {
  /**
   * @return the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   */
  String location();

  /**
   * @return the keystore password
   */
  char[] password();

  /**
   * @return the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>).
   */
  String type() default "";

  /**
   * @return the keystore provider (hint: Bouncy Castle is <code>BC</code>)
   */
  String provider() default "";

  /**
   * @return if true, the keystore location and password parameters are to be read using the
   *     following system properties:
   *     <ul>
   *       <li><code>javax.net.ssl.keyStore</code>
   *       <li><code>javax.net.ssl.keyStorePassword</code>
   *     </ul>
   *     <p>The keystore location supports the following protocols:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     <p>If no protocol is specified, <code>file</code> is assumed.
   *     <p>The default keystore type is <code>PKCS12</code>.
   */
  boolean useSystemProperties() default false;
}
