package com.mirkocaserta.bruce.mac;

/**
 * An interface for providing encoded Message Authentication Codes.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingMac {
  /**
   * Produces an encoded Message Authentication Code.
   *
   * @param message the input message
   * @return the encoded Message Authentication Code
   */
  String get(String message);
}
