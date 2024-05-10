package com.mirkocaserta.bruce.api;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Encoding;
import java.nio.charset.Charset;
import java.util.function.Function;

public interface Digester {
  /**
   * Returns a message digester for the given parameters.
   *
   * <p>This digester implementation assumes your input messages are using the {@link
   * Charset#defaultCharset()}.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param encoding the encoding
   * @return a message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  <T> Function<T, String> with(String algorithm, Encoding encoding);

  /**
   * Returns a message digester for the given parameters.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param encoding the encoding
   * @param charset the charset used for the input messages
   * @return a message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  <T, R> Function<T, R> with(
      String algorithm, Encoding encoding, Charset charset, Class<R> outputType);

  /**
   * Returns a message digester for the given parameters.
   *
   * <p>This digester implementation assumes your input messages are using the {@link
   * Charset#defaultCharset()}.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the encoding
   * @return a message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  <T, R> Function<T, R> with(
      String algorithm, String provider, Encoding encoding, Class<R> outputType);

  /**
   * Returns a message digester for the given parameters.
   *
   * @param <T> input type parameter
   * @param <R> output type parameter
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the encoding
   * @param charset the charset used for the input messages
   * @param outputType the output type class
   * @return a message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  <T, R> Function<T, R> with(
      String algorithm, String provider, Encoding encoding, Charset charset, Class<R> outputType);

  <T> Function<T, byte[]> with(String algorithm);

  /**
   * Returns a message digester for the given parameters.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  <T, R> Function<T, R> with(String algorithm, String provider, Class<R> outputType);

  /**
   * Returns a message digester for the given parameters.
   *
   * @param algorithm the algorithm (ex: SHA1, MD5, etc.)
   * @return a message digester
   * @throws BruceException on no such algorithm exception
   */
  <T, R> Function<T, R> with(String algorithm, Class<R> outputType);
}
