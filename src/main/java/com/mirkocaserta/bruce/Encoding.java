package com.mirkocaserta.bruce;

/**
 * Bruce supports these encodings. Encodings are used in cryptography as a wire safe representation
 * of raw bytes which would otherwise get screwed-up in all sort of possible ways while traversing
 * networks or, more generally, while exchanging hands.
 *
 * <p>Have you ever played the <a href="https://en.wikipedia.org/wiki/Chinese_whispers">telephone
 * game</a>? Computers do that with raw bytes as different architectures internally encode bytes in
 * different ways. Unless you use a standard encoding, messages get lost in translation with
 * catastrophic consequences.
 */
public enum Encoding {
  /**
   * Hexadecimal encoding. For instance, the hexadecimal encoding of a random MD5 hash is <code>
   * 78e731027d8fd50ed642340b7c9a63b3</code>.
   */
  HEX,
  /**
   * Base64 encoding. For instance, the Base64 encoding of a random MD5 hash is <code>
   * eOcxAn2P1Q7WQjQLfJpjsw==</code>.
   */
  BASE64,
  /**
   * URL encoding. For instance, the URL encoding of a random MD5 hash is <code>
   * eOcxAn2P1Q7WQjQLfJpjsw==</code>.
   */
  URL,
  /**
   * MIME encoding. For instance, the MIME encoding of a random MD5 hash is <code>
   * eOcxAn2P1Q7WQjQLfJpjsw==</code>.
   */
  MIME;

  public static Encoding defaultEncoding() {
    return BASE64;
  }
}
