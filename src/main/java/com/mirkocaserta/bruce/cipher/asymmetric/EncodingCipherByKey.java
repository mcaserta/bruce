package com.mirkocaserta.bruce.cipher.asymmetric;

import com.mirkocaserta.bruce.cipher.Mode;

/**
 * An interface for performing asymmetric encryption/decryption with encoded strings and keys
 * configured in an underlying mapping where the keys are indexed by logical name.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface EncodingCipherByKey {
  /**
   * Encrypts/decrypts a message based on the underlying mode of operation.
   *
   * @param keyId the key id
   * @param mode encryption or decryption mode
   * @param message if in encryption mode, the clear-text message, otherwise the encoded message to
   *     decrypt
   * @return if in encryption mode, the encoded encrypted message, otherwise the decrypted message
   */
  String encrypt(String keyId, Mode mode, String message);
}
