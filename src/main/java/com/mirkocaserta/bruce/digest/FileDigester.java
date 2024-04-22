package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.BruceException;
import java.io.File;

/**
 * Generic interface for getting file digests in an encoded format such as hexadecimal or base64.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public interface FileDigester {
  /**
   * Returns the file digest in encoded format.
   *
   * @param file the file to digest
   * @return the file digest in encoded format
   * @throws BruceException on digesting errors
   */
  String digest(File file);
}
