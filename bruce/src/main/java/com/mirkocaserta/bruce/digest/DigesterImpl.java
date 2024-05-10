package com.mirkocaserta.bruce.digest;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Encoding;
import com.mirkocaserta.bruce.api.Digester;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.function.Function;

public final class DigesterImpl implements Digester {
  private static final String BLANK = "";
  private static final String INVALID_ENCODING_NULL = "Invalid encoding: null";
  private static final String INVALID_OUTPUT_TYPE_NULL = "Invalid outputType: null";

  @Override
  public <T> Function<T, String> with(final String algorithm, final Encoding encoding) {
    return with(algorithm, BLANK, encoding, Charset.defaultCharset(), String.class);
  }

  @Override
  public <T, R> Function<T, R> with(
      final String algorithm,
      final Encoding encoding,
      final Charset charset,
      final Class<R> outputType) {
    return with(algorithm, BLANK, encoding, charset, outputType);
  }

  @Override
  public <T, R> Function<T, R> with(
      final String algorithm,
      final String provider,
      final Encoding encoding,
      final Class<R> outputType) {
    return with(algorithm, provider, encoding, Charset.defaultCharset(), outputType);
  }

  @Override
  public <T, R> Function<T, R> with(
      final String algorithm,
      final String provider,
      final Encoding encoding,
      final Charset charset,
      final Class<R> outputType) {
    if (encoding == null) {
      throw new BruceException(INVALID_ENCODING_NULL);
    }
    if (outputType == null) {
      throw new BruceException(INVALID_OUTPUT_TYPE_NULL);
    }
    try {
      final var digester =
          provider == null || provider.isBlank()
              ? MessageDigest.getInstance(algorithm)
              : MessageDigest.getInstance(algorithm, provider);

      return message -> {
        try (final InputStream inputStream = getInputStream(message, charset)) {
          final var buffer = new byte[8192];
          int read;

          while ((read = inputStream.read(buffer)) > 0) {
            digester.update(buffer, 0, read);
          }
          final byte[] output = digester.digest();
          if (byte[].class.equals(outputType)) {
            return outputType.cast(output);
          } else if (String.class.equals(outputType)) {
            return outputType.cast(Bruce.encode(encoding, output));
          } else if (File.class.equals(outputType)) {
            final var path = Files.createTempFile("digest", algorithm.toLowerCase());
            Files.writeString(path, Bruce.encode(encoding, output), charset);
            return outputType.cast(path.toFile());
          } else {
            throw new BruceException(
                String.format("Unsupported output message class: %s", outputType.getName()));
          }
        } catch (FileNotFoundException e) {
          throw new BruceException(
              String.format("No such file: %s", ((File) message).getAbsolutePath()), e);
        } catch (IOException e) {
          throw new BruceException("I/O error", e);
        }
      };
    } catch (NoSuchAlgorithmException e) {
      throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(String.format("No such provider: %s", provider), e);
    }
  }

  private static <T> InputStream getInputStream(final T message, final Charset charset) {
    if (message instanceof byte[] bytes) {
      return new ByteArrayInputStream(bytes);
    } else if (message instanceof String s) {
      return new ByteArrayInputStream(s.getBytes(charset));
    } else if (message instanceof File file) {
      try {
        return new FileInputStream(file);
      } catch (FileNotFoundException e) {
        throw new BruceException(String.format("No such file: %s", file), e);
      }
    } else {
      throw new BruceException(
          String.format("unsupported input message class: %s", message.getClass().getName()));
    }
  }

  @Override
  public <T> Function<T, byte[]> with(final String algorithm) {
    return with(algorithm, byte[].class);
  }

  @Override
  public <T, R> Function<T, R> with(
      final String algorithm, final String provider, final Class<R> outputType) {
    return with(algorithm, provider, Encoding.HEX, Charset.defaultCharset(), outputType);
  }

  @Override
  public <T, R> Function<T, R> with(final String algorithm, final Class<R> outputType) {
    return with(algorithm, BLANK, outputType);
  }
}
