package com.mirkocaserta.bruce;

import java.nio.charset.Charset;
import java.util.function.Function;

public interface Digester {
  <T> Function<T, String> with(String algorithm, Encoding encoding);

  <T, R> Function<T, R> with(
      String algorithm, Encoding encoding, Charset charset, Class<R> outputType);

  <T, R> Function<T, R> with(
      String algorithm, String provider, Encoding encoding, Class<R> outputType);

  <T, R> Function<T, R> with(
      String algorithm, String provider, Encoding encoding, Charset charset, Class<R> outputType);

  <T> Function<T, byte[]> with(String algorithm);

  <T, R> Function<T, R> with(String algorithm, String provider, Class<R> outputType);

  <T, R> Function<T, R> with(String algorithm, Class<R> outputType);
}
