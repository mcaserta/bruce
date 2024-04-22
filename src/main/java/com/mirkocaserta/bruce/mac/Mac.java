package com.mirkocaserta.bruce.mac;

/**
 * An interface for providing Message Authentication Codes.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface Mac {
  /**
   * Produces the Message Authentication Code.
   *
   * @param message the input message
   * @return the Message Authentication Code
   */
  byte[] get(byte[] message);
}
