package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipher;
import com.mirkocaserta.bruce.cipher.symmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.FileDigester;
import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;
import com.mirkocaserta.bruce.signature.*;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.util.Hex;
import com.mirkocaserta.bruce.util.Pair;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is the main entrypoint for all cryptographic operations.
 *
 * <p>Just type <code>Bruce.</code> in your IDE and let autocompletion do the rest.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bruce {
  /** The default keystore format/type. */
  public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

  private static final Hex.Encoder HEX_ENCODER = Hex.getEncoder();
  private static final Base64.Encoder BASE_64_ENCODER = Base64.getEncoder();
  private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder();
  private static final Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder();
  private static final Hex.Decoder HEX_DECODER = Hex.getDecoder();
  private static final Base64.Decoder BASE_64_DECODER = Base64.getDecoder();
  private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
  private static final Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();

  private static final String BLANK = "";
  private static final String INVALID_ENCODING_NULL = "Invalid encoding: null";
  private static final String MODE_CANNOT_BE_NULL = "mode cannot be null";

  private static final ConcurrentMap<String, Cipher> cipherCache = new ConcurrentHashMap<>();

  private Bruce() {
    // utility class, users can't make new instances
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
   * <p>The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
   *
   * @return the default keystore
   * @throws BruceException on loading errors
   */
  public static KeyStore keystore() {
    return keystore(DEFAULT_KEYSTORE_TYPE);
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
   * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @return the default keystore
   * @throws BruceException on loading errors
   */
  public static KeyStore keystore(String type) {
    return keystore(
        System.getProperty("javax.net.ssl.keyStore"),
        Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"))
            .orElse(BLANK)
            .toCharArray(),
        type);
  }

  /**
   * Returns a key store. The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
   *
   * @param location the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @return a key store
   * @throws BruceException on loading errors
   */
  public static KeyStore keystore(String location, char[] password) {
    return keystore(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
  }

  /**
   * Returns a key store.
   *
   * @param location the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @return a key store
   * @throws BruceException on loading errors
   */
  public static KeyStore keystore(String location, char[] password, String type) {
    return keystore(location, password, type, BLANK);
  }

  /**
   * Returns a key store.
   *
   * @param location the keystore location. The following protocols are supported:
   *     <ul>
   *       <li><code>classpath:</code>
   *       <li><code>http:</code>
   *       <li><code>https:</code>
   *       <li><code>file:</code>
   *     </ul>
   *     If no protocol is specified, <code>file</code> is assumed.
   * @param password the password
   * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a key store
   * @throws BruceException on loading errors
   */
  public static KeyStore keystore(String location, char[] password, String type, String provider) {
    if (location == null || location.isBlank()) {
      throw new BruceException("please provide a valid key store location");
    }

    try {
      var keyStore =
          provider == null || provider.isBlank()
              ? KeyStore.getInstance(type)
              : KeyStore.getInstance(type, provider);
      InputStream inputStream;
      if (location.startsWith("classpath:")) {
        inputStream = Bruce.class.getResourceAsStream(location.replaceFirst("classpath:", BLANK));
      } else if (location.matches("^https*://.*$")) {
        inputStream = new URL(location).openConnection().getInputStream();
      } else {
        inputStream = Files.newInputStream(Path.of(location.replaceFirst("file:", BLANK)));
      }
      keyStore.load(inputStream, password);
      return keyStore;
    } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
      throw new BruceException(String.format("error loading keystore: location=%s", location), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(
          String.format("error loading keystore, no such provider: provider=%s", provider), e);
    } catch (Exception e) {
      throw new BruceException("error loading keystore", e);
    }
  }

  /**
   * Loads a certificate from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the certificate alias
   * @return the certificate
   * @throws BruceException on loading errors
   */
  public static Certificate certificate(KeyStore keystore, String alias) {
    try {
      var certificate = keystore.getCertificate(alias);

      if (certificate == null) {
        throw new BruceException(String.format("certificate not found for alias: %s", alias));
      }

      return certificate;
    } catch (KeyStoreException e) {
      throw new BruceException(String.format("error loading certificate with alias: %s", alias), e);
    }
  }

  /**
   * Loads a public key from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the certificate alias
   * @return the public key
   * @throws BruceException on loading errors
   */
  public static PublicKey publicKey(KeyStore keystore, String alias) {
    return certificate(keystore, alias).getPublicKey();
  }

  /**
   * Loads a private key from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the certificate alias
   * @param password the private key password
   * @return the private key
   * @throws BruceException on loading errors
   */
  public static PrivateKey privateKey(KeyStore keystore, String alias, char[] password) {
    try {
      var privateKeyEntry =
          (KeyStore.PrivateKeyEntry)
              keystore.getEntry(alias, new KeyStore.PasswordProtection(password));

      if (privateKeyEntry == null) {
        throw new BruceException(String.format("no such private key with alias: %s", alias));
      }

      return privateKeyEntry.getPrivateKey();
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
      throw new BruceException(String.format("error loading private key with alias: %s", alias), e);
    }
  }

  /**
   * Loads a secret key from the given keystore.
   *
   * @param keystore the keystore to read from
   * @param alias the secret key alias
   * @param password the secret key password
   * @return the secret key
   * @throws BruceException on loading errors
   */
  public static Key secretKey(KeyStore keystore, String alias, char[] password) {
    try {
      var key = keystore.getKey(alias, password);

      if (key == null) {
        throw new BruceException(String.format("no such secret key with alias: %s", alias));
      }

      return key;
    } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
      throw new BruceException(String.format("error loading secret key with alias: %s", alias), e);
    }
  }

  /**
   * Generates a key pair.
   *
   * @param algorithm the key algorithm
   * @param keySize the key size
   * @return the key pair
   */
  public static KeyPair keyPair(String algorithm, int keySize) {
    return keyPair(algorithm, null, keySize, null);
  }

  /**
   * Generates a key pair.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param keySize the key size
   * @return the key pair
   */
  public static KeyPair keyPair(String algorithm, String provider, int keySize) {
    return keyPair(algorithm, provider, keySize, null);
  }

  /**
   * Generates a key pair with the specified random number generator.
   *
   * @param algorithm the key algorithm
   * @param keySize the key size
   * @param random the random number generator
   * @return the key pair
   */
  public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
    return keyPair(algorithm, null, keySize, random);
  }

  /**
   * Generates a key pair with the specified provider and random number generator.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param keySize the key size
   * @param random the random number generator
   * @return the key pair
   */
  public static KeyPair keyPair(
      String algorithm, String provider, int keySize, SecureRandom random) {
    try {
      var keyGen =
          provider == null || provider.isBlank()
              ? KeyPairGenerator.getInstance(algorithm)
              : KeyPairGenerator.getInstance(algorithm, provider);

      if (random == null) {
        keyGen.initialize(keySize);
      } else {
        keyGen.initialize(keySize, random);
      }
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new BruceException(String.format("no such algorithm: %s", algorithm), e);
    } catch (InvalidParameterException e) {
      throw new BruceException(String.format("invalid key size: %d", keySize), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(String.format("no such provider: %s", provider), e);
    }
  }

  /**
   * Returns an encoding message digester for the given algorithm.
   *
   * <p>This digester implementation assumes your input messages are using the {@link
   * Charset#defaultCharset()}.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param encoding the encoding
   * @return an encoding message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Digester digester(String algorithm, Encoding encoding) {
    return digester(algorithm, BLANK, encoding, Charset.defaultCharset());
  }

  /**
   * Returns an encoding message digester for the given algorithm and character set.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param encoding the encoding
   * @param charset the charset used for the input messages
   * @return an encoding message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Digester digester(String algorithm, Encoding encoding, Charset charset) {
    return digester(algorithm, BLANK, encoding, charset);
  }

  /**
   * Returns an encoding message digester for the given algorithm and provider.
   *
   * <p>This digester implementation assumes your input messages are using the {@link
   * Charset#defaultCharset()}.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the encoding
   * @return an encoding message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Digester digester(String algorithm, String provider, Encoding encoding) {
    return digester(algorithm, provider, encoding, Charset.defaultCharset());
  }

  /**
   * Returns an encoding message digester for the given algorithm and provider.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the encoding
   * @param charset the charset used for the input messages
   * @return an encoding message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Digester digester(
      String algorithm, String provider, Encoding encoding, Charset charset) {
    if (encoding == null) {
      throw new BruceException(INVALID_ENCODING_NULL);
    }

    var rawDigester =
        provider == null || provider.isBlank()
            ? digester(algorithm)
            : digester(algorithm, provider);

    return new Digester() {
      @Override
      public byte[] digest(byte[] message) {
        return rawDigester.digest(message);
      }

      @Override
      public String digest(String message) {
        return encode(encoding, rawDigester.digest(message.getBytes(charset)));
      }
    };
  }

  /**
   * Returns an encoding file digester for the given algorithm.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param encoding the encoding
   * @return an encoding file digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static FileDigester fileDigester(String algorithm, Encoding encoding) {
    return fileDigester(algorithm, BLANK, encoding);
  }

  /**
   * Returns an encoding file digester for the given algorithm and provider.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the encoding
   * @return an encoding file digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static FileDigester fileDigester(String algorithm, String provider, Encoding encoding) {
    if (encoding == null) {
      throw new BruceException(INVALID_ENCODING_NULL);
    }

    try { // fail fast
      if (provider == null || provider.isBlank()) {
        MessageDigest.getInstance(algorithm);
      } else {
        MessageDigest.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(String.format("No such provider: %s", provider), e);
    }

    return file -> {
      try {
        var digest =
            provider == null || provider.isBlank()
                ? MessageDigest.getInstance(algorithm)
                : MessageDigest.getInstance(algorithm, provider);
        try (var inputStream = new FileInputStream(file)) {
          var buffer = new byte[8192];
          int read;

          while ((read = inputStream.read(buffer)) > 0) {
            digest.update(buffer, 0, read);
          }
        }
        return encode(encoding, digest.digest());
      } catch (NoSuchAlgorithmException e) {
        throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
      } catch (NoSuchProviderException e) {
        throw new BruceException(String.format("No such provider: %s", provider), e);
      } catch (FileNotFoundException e) {
        throw new BruceException(String.format("No such file: %s", file), e);
      } catch (IOException e) {
        throw new BruceException(String.format("I/O error reading file: %s", file), e);
      }
    };
  }

  /**
   * Returns a raw byte array message digester for the given algorithm and provider.
   *
   * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc.)
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a raw byte array message digester
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Digester digester(String algorithm, String provider) {
    MessageDigest digester;

    try {
      digester =
          provider == null || provider.isBlank()
              ? MessageDigest.getInstance(algorithm)
              : MessageDigest.getInstance(algorithm, provider);
    } catch (NoSuchAlgorithmException e) {
      throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
    } catch (NoSuchProviderException e) {
      throw new BruceException(String.format("No such provider: %s", provider), e);
    }

    return new Digester() {
      @Override
      public byte[] digest(byte[] message) {
        return digester.digest(message);
      }

      @Override
      public String digest(String message) {
        return encode(
            Encoding.defaultEncoding(),
            digester.digest(message.getBytes(Charset.defaultCharset())));
      }
    };
  }

  /**
   * Returns a raw byte array message digester for the given algorithm.
   *
   * @param algorithm the algorithm (ex: SHA1, MD5, etc.)
   * @return a raw byte array message digester
   * @throws BruceException on no such algorithm exception
   */
  public static Digester digester(String algorithm) {
    return digester(algorithm, BLANK);
  }

  /**
   * Returns a signer for the given private key and algorithm.
   *
   * @param privateKey the signing key
   * @param algorithm the signing algorithm
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Signer signer(PrivateKey privateKey, String algorithm) {
    return signer(privateKey, algorithm, BLANK);
  }

  /**
   * Returns a signer for the given private key, algorithm and provider.
   *
   * @param privateKey the signing key
   * @param algorithm the signing algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Signer signer(PrivateKey privateKey, String algorithm, String provider) {
    final var signer =
        new Signer() {
          @Override
          public byte[] sign(byte[] message) {
            try {
              var signature = getSignature(algorithm, provider);
              signature.initSign(privateKey);
              signature.update(message);
              return signature.sign();
            } catch (SignatureException | InvalidKeyException e) {
              throw new BruceException(
                  String.format(
                      "error generating the signature: algorithm=%s, provider=%s",
                      algorithm, provider),
                  e);
            }
          }

          @Override
          public String sign(String message) {
            return encode(Encoding.defaultEncoding(), message.getBytes(Charset.defaultCharset()));
          }
        };
    /*
    This is here in order to trigger exceptions at initialization time
    rather than at runtime when invoking the sign method on the signer.
     */
    signer.sign("FAIL FAST".getBytes(Charset.defaultCharset()));
    return signer;
  }

  private static Signature getSignature(String algorithm, String provider) {
    try {
      return provider == null || provider.isBlank()
          ? Signature.getInstance(algorithm)
          : Signature.getInstance(algorithm, provider);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new BruceException(
          String.format("error getting signer: algorithm=%s, provider=%s", algorithm, provider), e);
    }
  }

  /**
   * Returns a signer where the private key can be chosen at runtime. The signing keys must be
   * provided in a map where the map key is an alias to the signing key and the value is the
   * corresponding signing key.
   *
   * @param privateKeyMap the signing key map
   * @param algorithm the signing algorithm
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm) {
    return signer(privateKeyMap, algorithm, BLANK);
  }

  /**
   * Returns a signer where the private key can be chosen at runtime. The signing keys must be
   * provided in a map where the map key is an alias to the signing key and the value is the
   * corresponding signing key.
   *
   * @param privateKeyMap the signing key map
   * @param algorithm the signing algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static SignerByKey signer(
      Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
    return (privateKeyId, message) -> {
      var privateKey = privateKeyMap.get(privateKeyId);

      if (privateKey == null) {
        throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
      }

      return signer(privateKey, algorithm, provider).sign(message);
    };
  }

  /**
   * Returns an encoding signer where the private key can be chosen at runtime. The signing keys
   * must be provided in a map where the map key is an alias to the signing key and the value is the
   * corresponding signing key.
   *
   * <p>The implementation assumes your input messages use the <code>UTF-8</code> charset.
   *
   * @param privateKeyMap the signing key map
   * @param algorithm the signing algorithm
   * @param encoding the signature encoding
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static EncodingSignerByKey signer(
      Map<String, PrivateKey> privateKeyMap, String algorithm, Encoding encoding) {
    return signer(privateKeyMap, algorithm, null, Charset.defaultCharset(), encoding);
  }

  /**
   * Returns an encoding signer where the private key can be chosen at runtime. The signing keys
   * must be provided in a map where the map key is an alias to the signing key and the value is the
   * corresponding signing key.
   *
   * @param privateKeyMap the signing key map
   * @param algorithm the signing algorithm
   * @param charset the charset used in messages
   * @param encoding the signature encoding
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static EncodingSignerByKey signer(
      Map<String, PrivateKey> privateKeyMap, String algorithm, Charset charset, Encoding encoding) {
    return signer(privateKeyMap, algorithm, null, charset, encoding);
  }

  /**
   * Returns an encoding signer where the private key can be chosen at runtime. The signing keys
   * must be provided in a map where the map key is an alias to the signing key and the value is the
   * corresponding signing key.
   *
   * @param privateKeyMap the signing key map
   * @param algorithm the signing algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param charset the charset used in messages
   * @param encoding the signature encoding
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static EncodingSignerByKey signer(
      Map<String, PrivateKey> privateKeyMap,
      String algorithm,
      String provider,
      Charset charset,
      Encoding encoding) {
    return (privateKeyId, message) -> {
      var privateKey = privateKeyMap.get(privateKeyId);

      if (privateKey == null) {
        throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
      }

      return signer(privateKey, algorithm, provider, charset, encoding).sign(message);
    };
  }

  /**
   * Returns an encoding signer for the given private key using the default provider and {@link
   * Charset#defaultCharset()} as the default charset used in messages.
   *
   * @param privateKey the signing key
   * @param algorithm the signing algorithm
   * @param encoding the signature encoding
   * @return the signer
   * @throws BruceException on initialization exceptions
   */
  public static Signer signer(PrivateKey privateKey, String algorithm, Encoding encoding) {
    return signer(privateKey, algorithm, BLANK, Charset.defaultCharset(), encoding);
  }

  /**
   * Returns an encoding signer for the given private key using the default provider.
   *
   * @param privateKey the signing key
   * @param algorithm the signing algorithm
   * @param charset the charset used in messages
   * @param encoding the signature encoding
   * @return the signer
   * @throws BruceException on initialization exceptions
   */
  public static Signer signer(
      PrivateKey privateKey, String algorithm, Charset charset, Encoding encoding) {
    return signer(privateKey, algorithm, BLANK, charset, encoding);
  }

  /**
   * Returns an encoding signer for the given private key.
   *
   * @param privateKey the signing key
   * @param algorithm the signing algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param charset the charset used in messages
   * @param encoding the signature encoding
   * @return the signer
   * @throws BruceException on initialization exceptions
   */
  public static Signer signer(
      PrivateKey privateKey,
      String algorithm,
      String provider,
      Charset charset,
      Encoding encoding) {
    if (encoding == null) {
      throw new BruceException(INVALID_ENCODING_NULL);
    }

    if (charset == null) {
      throw new BruceException("Invalid charset: null");
    }

    final var signer = signer(privateKey, algorithm, provider);

    return new Signer() {
      @Override
      public byte[] sign(byte[] message) {
        return signer.sign(message);
      }

      @Override
      public String sign(String message) {
        return encode(encoding, signer.sign(message.getBytes(charset)));
      }
    };
  }

  /**
   * Returns a verifier for the given public key and algorithm using the default provider.
   *
   * @param publicKey the verification key
   * @param algorithm the verification algorithm
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Verifier verifier(PublicKey publicKey, String algorithm) {
    return verifier(publicKey, algorithm, BLANK);
  }

  /**
   * Returns a verifier for the given public key, algorithm and provider.
   *
   * @param publicKey the verification key
   * @param algorithm the verification algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Verifier verifier(PublicKey publicKey, String algorithm, String provider) {
    return new Verifier() {
      @Override
      public boolean verify(byte[] message, byte[] signature) {
        try {
          var signatureInstance = getSignature(algorithm, provider);
          signatureInstance.initVerify(publicKey);
          signatureInstance.update(message);
          return signatureInstance.verify(signature);
        } catch (InvalidKeyException e) {
          throw new BruceException(
              String.format(
                  "error verifying the signature: algorithm=%s, provider=%s", algorithm, provider),
              e);
        } catch (SignatureException e) {
          return false;
        }
      }

      @Override
      public boolean verify(String message, String signature) {
        return verify(
            message.getBytes(Charset.defaultCharset()),
            decode(Encoding.defaultEncoding(), signature));
      }
    };
  }

  /**
   * Returns a verifier where the public key can be chosen at runtime. The verification keys must be
   * provided in a map where the map key is an alias to the verification key and the value is the
   * corresponding verification key. This method uses the default provider.
   *
   * @param publicKeyMap the verification key map
   * @param algorithm the verification algorithm
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm) {
    return verifier(publicKeyMap, algorithm, BLANK);
  }

  /**
   * Returns a verifier where the public key can be chosen at runtime. The verification keys must be
   * provided in a map where the map key is an alias to the verification key and the value is the
   * corresponding verification key.
   *
   * @param publicKeyMap the verification key map
   * @param algorithm the verification algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static VerifierByKey verifier(
      Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
    return (publicKeyId, message, signature) -> {
      var publicKey = publicKeyMap.get(publicKeyId);

      if (publicKey == null) {
        throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
      }

      return verifier(publicKey, algorithm, provider).verify(message, signature);
    };
  }

  /**
   * Returns an encoding verifier for the given public key. This method assumes the default messages
   * charset is {@link Charset#defaultCharset()}. The default provider is used.
   *
   * @param publicKey the verification key
   * @param algorithm the verification algorithm
   * @param encoding the verification encoding
   * @return the verifier
   * @throws BruceException on initialization exceptions
   */
  public static Verifier verifier(PublicKey publicKey, String algorithm, Encoding encoding) {
    return verifier(publicKey, algorithm, BLANK, encoding);
  }

  /**
   * Returns an encoding verifier for the given public key. This method assumes the default messages
   * charset is {@link Charset#defaultCharset()}.
   *
   * @param publicKey the verification key
   * @param algorithm the verification algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the verification encoding
   * @return the verifier
   * @throws BruceException on initialization exceptions
   */
  public static Verifier verifier(
      PublicKey publicKey, String algorithm, String provider, Encoding encoding) {
    return verifier(publicKey, algorithm, provider, Charset.defaultCharset(), encoding);
  }

  /**
   * Returns an encoding verifier for the given public key.
   *
   * @param publicKey the verification key
   * @param algorithm the verification algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param charset the charset used in messages
   * @param encoding the verification encoding
   * @return the verifier
   * @throws BruceException on initialization exceptions
   */
  public static Verifier verifier(
      PublicKey publicKey, String algorithm, String provider, Charset charset, Encoding encoding) {
    if (encoding == null) {
      throw new BruceException(INVALID_ENCODING_NULL);
    }

    if (charset == null) {
      throw new BruceException("Invalid charset: null");
    }

    final var verifier = verifier(publicKey, algorithm, provider);
    return new Verifier() {
      @Override
      public boolean verify(byte[] message, byte[] signature) {
        return verifier.verify(message, signature);
      }

      @Override
      public boolean verify(String message, String signature) {
        return verifier.verify(message.getBytes(charset), decode(encoding, signature));
      }
    };
  }

  /**
   * Returns an encoding verifier where the public key can be chosen at runtime. The verification
   * keys must be provided in a map where the map key is an alias to the verification key and the
   * value is the corresponding verification key.
   *
   * <p>The implementation assumes your input messages use the {@link Charset#defaultCharset()}.
   *
   * @param publicKeyMap the verification key map
   * @param algorithm the verification algorithm
   * @param encoding the verification encoding
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static EncodingVerifierByKey verifier(
      Map<String, PublicKey> publicKeyMap, String algorithm, Encoding encoding) {
    return verifier(publicKeyMap, algorithm, null, Charset.defaultCharset(), encoding);
  }

  /**
   * Returns an encoding verifier where the public key can be chosen at runtime. The verification
   * keys must be provided in a map where the map key is an alias to the verification key and the
   * value is the corresponding verification key.
   *
   * @param publicKeyMap the verification key map
   * @param algorithm the verification algorithm
   * @param charset the charset used in messages
   * @param encoding the verification encoding
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static EncodingVerifierByKey verifier(
      Map<String, PublicKey> publicKeyMap, String algorithm, Charset charset, Encoding encoding) {
    return verifier(publicKeyMap, algorithm, null, charset, encoding);
  }

  /**
   * Returns an encoding verifier where the public key can be chosen at runtime. The verification
   * keys must be provided in a map where the map key is an alias to the verification key and the
   * value is the corresponding verification key.
   *
   * @param publicKeyMap the verification key map
   * @param algorithm the verification algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param charset the charset used in messages
   * @param encoding the verification encoding
   * @return the verifier
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static EncodingVerifierByKey verifier(
      Map<String, PublicKey> publicKeyMap,
      String algorithm,
      String provider,
      Charset charset,
      Encoding encoding) {
    return (publicKeyId, message, signature) -> {
      var publicKey = publicKeyMap.get(publicKeyId);

      if (publicKey == null) {
        throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
      }

      return verifier(publicKey, algorithm, provider, charset, encoding).verify(message, signature);
    };
  }

  /**
   * Generates a symmetric key using the specified algorithm.
   *
   * @param algorithm the key algorithm
   * @return a newly generated symmetric key
   */
  public static byte[] symmetricKey(String algorithm) {
    return symmetricKey(algorithm, BLANK);
  }

  /**
   * Generates a symmetric key using the specified algorithm and provider.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a newly generated symmetric key
   */
  public static byte[] symmetricKey(String algorithm, String provider) {
    try {
      var generator =
          provider == null || provider.isBlank()
              ? KeyGenerator.getInstance(algorithm)
              : KeyGenerator.getInstance(algorithm, provider);
      generator.init(new SecureRandom());
      return generator.generateKey().getEncoded();
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new BruceException(
          String.format("cannot generate key: algorithm=%s, provider=%s", algorithm, provider), e);
    }
  }

  /**
   * Generates an encoded symmetric key using the specified algorithm.
   *
   * @param algorithm the key algorithm
   * @param encoding the key encoding
   * @return a newly generated symmetric key
   */
  public static String symmetricKey(String algorithm, Encoding encoding) {
    return symmetricKey(algorithm, BLANK, encoding);
  }

  /**
   * Generates an encoded symmetric key using the specified algorithm and provider.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the key encoding
   * @return a newly generated symmetric key
   */
  public static String symmetricKey(String algorithm, String provider, Encoding encoding) {
    return encode(encoding, symmetricKey(algorithm, provider));
  }

  /**
   * Returns a symmetric cipher where the key is selectable at runtime through the returned
   * interface.
   *
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param mode the encryption mode
   * @return the symmetric cipher
   */
  public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
    return cipher(keyAlgorithm, cipherAlgorithm, BLANK, mode);
  }

  /**
   * Returns a symmetric cipher where the key is selectable at runtime through the returned
   * interface.
   *
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param mode the encryption mode
   * @return the symmetric cipher
   */
  public static CipherByKey cipher(
      String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
    if (mode == null) {
      throw new BruceException(MODE_CANNOT_BE_NULL);
    }

    return (key, iv, message) -> {
      try {
        var initializationVectorSpec = new IvParameterSpec(iv);
        var spec = new SecretKeySpec(key, keyAlgorithm);
        var cipher =
            provider == null || provider.isBlank()
                ? javax.crypto.Cipher.getInstance(cipherAlgorithm)
                : javax.crypto.Cipher.getInstance(cipherAlgorithm, provider);
        switch (mode) {
          case ENCRYPT ->
              cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, spec, initializationVectorSpec);
          case DECRYPT ->
              cipher.init(javax.crypto.Cipher.DECRYPT_MODE, spec, initializationVectorSpec);
        }
        return cipher.doFinal(message);
      } catch (NoSuchAlgorithmException
          | BadPaddingException
          | InvalidKeyException
          | InvalidAlgorithmParameterException
          | NoSuchPaddingException
          | NoSuchProviderException
          | IllegalBlockSizeException e) {
        throw new BruceException("error encrypting/decrypting message", e);
      }
    };
  }

  /**
   * Returns a symmetric cipher.
   *
   * @param key the ciphering key
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param mode the encryption mode
   * @return the symmetric cipher
   */
  public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(
      byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
    return cipher(key, keyAlgorithm, cipherAlgorithm, BLANK, mode);
  }

  /**
   * Returns a symmetric cipher.
   *
   * @param key the ciphering key
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param mode the encryption mode
   * @return the symmetric cipher
   */
  public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(
      byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
    var cipher = cipher(keyAlgorithm, cipherAlgorithm, provider, mode);
    return (iv, message) -> cipher.encrypt(key, iv, message);
  }

  /**
   * Returns a symmetric cipher where the key is selectable at runtime through the returned
   * interface.
   *
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param mode the encryption mode
   * @param charset the message charset
   * @return the symmetric cipher
   */
  public static EncodingCipherByKey cipherByKey(
      String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
    return cipherByKey(keyAlgorithm, cipherAlgorithm, BLANK, mode, charset);
  }

  /**
   * Returns a symmetric cipher where the key is selectable at runtime through the returned
   * interface.
   *
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param mode the encryption mode
   * @param charset the message charset
   * @return the symmetric cipher
   */
  public static EncodingCipherByKey cipherByKey(
      String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
    var cipher = cipher(keyAlgorithm, cipherAlgorithm, provider, mode);

    return (key, iv, message, encoding) -> {
      var keyBA = decode(encoding, key);
      var ivBA = decode(encoding, iv);

      return switch (mode) {
        case ENCRYPT -> encode(encoding, cipher.encrypt(keyBA, ivBA, message.getBytes(charset)));
        case DECRYPT -> new String(cipher.encrypt(keyBA, ivBA, decode(encoding, message)), charset);
      };
    };
  }

  /**
   * Returns a symmetric cipher.
   *
   * @param key the encryption/decryption key
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param mode the encryption mode
   * @param charset the message charset
   * @param encoding the message encoding
   * @return the symmetric cipher
   */
  public static EncodingCipher cipher(
      String key,
      String keyAlgorithm,
      String cipherAlgorithm,
      Mode mode,
      Charset charset,
      Encoding encoding) {
    return cipher(key, keyAlgorithm, cipherAlgorithm, BLANK, mode, charset, encoding);
  }

  /**
   * Returns a symmetric cipher.
   *
   * @param key the encryption/decryption key
   * @param keyAlgorithm the key's algorithm
   * @param cipherAlgorithm the cipher's algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param mode the encryption mode
   * @param charset the message charset
   * @param encoding the message encoding
   * @return the symmetric cipher
   */
  public static EncodingCipher cipher(
      String key,
      String keyAlgorithm,
      String cipherAlgorithm,
      String provider,
      Mode mode,
      Charset charset,
      Encoding encoding) {
    var cipher = cipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
    return (iv, message) -> cipher.encrypt(key, iv, message, encoding);
  }

  /**
   * Returns an asymmetric cipher.
   *
   * @param key the ciphering key
   * @param algorithm the algorithm
   * @param mode the encryption mode
   * @return the asymmetric cipher
   */
  public static Cipher cipher(Key key, String algorithm, Mode mode) {
    return cipher(key, algorithm, BLANK, mode);
  }

  /**
   * Returns an asymmetric cipher.
   *
   * @param key the ciphering key
   * @param algorithm the algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param mode the encryption mode
   * @return the asymmetric cipher
   */
  public static Cipher cipher(Key key, String algorithm, String provider, Mode mode) {
    if (mode == null) {
      throw new BruceException(MODE_CANNOT_BE_NULL);
    }

    return message -> {
      try {
        var cipher =
            provider == null || provider.isBlank()
                ? javax.crypto.Cipher.getInstance(algorithm)
                : javax.crypto.Cipher.getInstance(algorithm, provider);
        switch (mode) {
          case ENCRYPT -> cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
          case DECRYPT -> cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        }
        return cipher.doFinal(message);
      } catch (Exception e) {
        throw new BruceException(
            String.format("error encrypting/decrypting message; mode=%s", mode), e);
      }
    };
  }

  /**
   * Returns an asymmetric cipher with a map of preconfigured keys.
   *
   * @param keys a map of keys where the key is the key id and the value is the key
   * @param algorithm the algorithm
   * @return an asymmetric cipher with a map of preconfigured keys
   */
  public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(
      Map<String, Key> keys, String algorithm) {
    return cipher(keys, algorithm, BLANK);
  }

  /**
   * Returns an asymmetric cipher with a map of preconfigured keys.
   *
   * @param keys a map of keys where the key is the key id and the value is the key
   * @param algorithm the algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return an asymmetric cipher with a map of preconfigured keys
   */
  public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(
      Map<String, Key> keys, String algorithm, String provider) {
    // we use a cipher cache here as getting a new one each time is a bit expensive
    return (keyId, mode, message) ->
        getCipher(keys, keyId, algorithm, provider, mode).encrypt(message);
  }

  /**
   * Returns an encoding asymmetric cipher.
   *
   * @param key the cipher's key
   * @param algorithm the algorithm
   * @param mode the cipher mode: encrypt/decrypt
   * @param encoding the message encoding
   * @param charset the message charset
   * @return an encoding asymmetric cipher
   */
  public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(
      Key key, String algorithm, Mode mode, Encoding encoding, Charset charset) {
    return cipher(key, algorithm, BLANK, mode, encoding, charset);
  }

  /**
   * Returns an encoding asymmetric cipher.
   *
   * @param key the cipher's key
   * @param algorithm the algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param mode the cipher mode: encrypt/decrypt
   * @param encoding the message encoding
   * @param charset the message charset
   * @return an encoding asymmetric cipher
   */
  public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(
      Key key, String algorithm, String provider, Mode mode, Encoding encoding, Charset charset) {
    var cipher = cipher(key, algorithm, provider, mode);
    return message -> crypt(cipher, message, mode, encoding, charset);
  }

  /**
   * Returns an encoding asymmetric cipher with a map of preconfigured keys.
   *
   * @param keys a map of keys where the key is the key id and the value is the key
   * @param algorithm the algorithm
   * @param encoding the message encoding
   * @param charset the message charset
   * @return an encoding asymmetric cipher with a map of preconfigured keys
   */
  public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(
      Map<String, Key> keys, String algorithm, Encoding encoding, Charset charset) {
    return cipher(keys, algorithm, BLANK, encoding, charset);
  }

  /**
   * Returns an encoding asymmetric cipher with a map of preconfigured keys.
   *
   * @param keys a map of keys where the key is the key id and the value is the key
   * @param algorithm the algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the message encoding
   * @param charset the message charset
   * @return an encoding asymmetric cipher with a map of preconfigured keys
   */
  public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(
      Map<String, Key> keys,
      String algorithm,
      String provider,
      Encoding encoding,
      Charset charset) {
    return (keyId, mode, message) -> {
      var cipher = getCipher(keys, keyId, algorithm, provider, mode);
      return crypt(cipher, message, mode, encoding, charset);
    };
  }

  /**
   * Performs encryption or decryption based on the given mode.
   *
   * @param cipher the encryption/decryption cipher
   * @param message the message
   * @param mode the cipher mode: encrypt/decrypt
   * @param encoding the message encoding
   * @param charset the message charset
   * @return the encrypted or decrypted message
   */
  private static String crypt(
      Cipher cipher, String message, Mode mode, Encoding encoding, Charset charset) {
    return switch (mode) {
      case ENCRYPT -> encode(encoding, cipher.encrypt(message.getBytes(charset)));
      case DECRYPT -> new String(cipher.encrypt(decode(encoding, message)), charset);
    };
  }

  /**
   * Returns a cipher using an internal cache.
   *
   * @param keys a map of keys where keyId is the map key and the cipher key is the value
   * @param keyId the key id
   * @param algorithm the cipher algorithm
   * @param provider the provider
   * @param mode the cipher mode: encrypt/decrypt
   * @return the cipher
   */
  private static Cipher getCipher(
      Map<String, Key> keys, String keyId, String algorithm, String provider, Mode mode) {
    return cipherCache.computeIfAbsent(
        cipherCacheKey(keyId, algorithm, provider, mode),
        ignored -> {
          var key = keys.get(keyId);
          if (key == null) {
            throw new BruceException(String.format("no such key: %s", keyId));
          }
          return cipher(key, algorithm, provider, mode);
        });
  }

  /**
   * This is used to generate the cipher cache key.
   *
   * @param keyId the key id
   * @param algorithm the cypher algorithm
   * @param provider the cypher provider
   * @param mode the cyphering mode: encrypt/decrypt
   * @return the cache key
   */
  private static String cipherCacheKey(String keyId, String algorithm, String provider, Mode mode) {
    return keyId + "::" + algorithm + "::" + provider + "::" + mode;
  }

  /**
   * Returns an interface for producing message authentication codes.
   *
   * @param key the secret key for digesting the messages
   * @param algorithm the signature algorithm
   * @return the message authentication codes interface
   */
  public static Mac mac(Key key, String algorithm) {
    return mac(key, algorithm, BLANK);
  }

  /**
   * Returns an interface for producing message authentication codes.
   *
   * @param key the secret key for digesting the messages
   * @param algorithm the signature algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return the message authentication codes interface
   */
  public static Mac mac(Key key, String algorithm, String provider) {
    return message -> {
      try {
        var mac =
            provider == null || provider.isBlank()
                ? javax.crypto.Mac.getInstance(algorithm)
                : javax.crypto.Mac.getInstance(algorithm, provider);
        mac.init(key);
        return mac.doFinal(message);
      } catch (NoSuchAlgorithmException e) {
        throw new BruceException(String.format("no such algorithm: %s", key.getAlgorithm()), e);
      } catch (InvalidKeyException e) {
        throw new BruceException("invalid key", e);
      } catch (NoSuchProviderException e) {
        throw new BruceException(String.format("no such provider: %s", provider), e);
      }
    };
  }

  /**
   * Returns an interface for producing encoded message authentication codes.
   *
   * @param key the secret key for digesting the messages
   * @param algorithm the signature algorithm
   * @param encoding the signature encoding
   * @param charset the message charset
   * @return the message authentication codes interface
   */
  public static EncodingMac mac(Key key, String algorithm, Encoding encoding, Charset charset) {
    return mac(key, algorithm, BLANK, encoding, charset);
  }

  /**
   * Returns an interface for producing encoded message authentication codes.
   *
   * @param key the secret key for digesting the messages
   * @param algorithm the signature algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @param encoding the signature encoding
   * @param charset the message charset
   * @return the message authentication codes interface
   */
  public static EncodingMac mac(
      Key key, String algorithm, String provider, Encoding encoding, Charset charset) {
    var mac = mac(key, algorithm, provider);
    return message -> encode(encoding, mac.get(message.getBytes(charset)));
  }

  /**
   * Decodes the input using the specified encoding.
   *
   * @param encoding the encoding to use
   * @param input the input to decode
   * @return a raw bytes array representation of the decoded input
   * @throws BruceException on decoding errors
   */
  private static byte[] decode(final Encoding encoding, final String input) {
    try {
      return switch (encoding) {
        case HEX -> HEX_DECODER.decode(input);
        case BASE64 -> BASE_64_DECODER.decode(input);
        case URL -> URL_DECODER.decode(input);
        case MIME -> MIME_DECODER.decode(input);
      };
    } catch (IllegalArgumentException e) {
      throw new BruceException(String.format("invalid input for encoding %s", encoding));
    }
  }

  /**
   * Encodes the input using the specified encoding.
   *
   * @param encoding the encoding to use
   * @param input the input to encode
   * @return a string representation of the encoded input
   */
  private static String encode(final Encoding encoding, final byte[] input) {
    return switch (encoding) {
      case HEX -> HEX_ENCODER.encodeToString(input);
      case BASE64 -> BASE_64_ENCODER.encodeToString(input);
      case URL -> URL_ENCODER.encodeToString(input);
      case MIME -> MIME_ENCODER.encodeToString(input);
    };
  }

  public static void instrument(final List<Object> objects) {
    for (final var object : objects) {
      instrument(object);
    }
  }

  public static void instrument(final Object object) {
    final var fields = Arrays.stream(object.getClass().getDeclaredFields()).toList();
    instrumentDigesters(fields, object);
    instrumentSigners(fields, object);
    instrumentVerifiers(fields, object);
  }

  private static void instrumentSigners(final List<Field> fields, final Object object) {
    fields.stream()
        .filter(field -> field.isAnnotationPresent(com.mirkocaserta.bruce.annotations.Signer.class))
        .map(
            field ->
                Pair.of(
                    field,
                    field.getDeclaredAnnotation(com.mirkocaserta.bruce.annotations.Signer.class)))
        .forEach(
            pair -> {
              pair.key().setAccessible(true);
              final var signerAnnotation = pair.val();
              final var privateKeyAnnotation = signerAnnotation.privateKey();
              final var keyStoreAnnotation = privateKeyAnnotation.keystore();
              final var keystore =
                  keystore(
                      keyStoreAnnotation.location(),
                      keyStoreAnnotation.password(),
                      keyStoreAnnotation.type(),
                      keyStoreAnnotation.provider());
              final var privateKey =
                  privateKey(
                      keystore, privateKeyAnnotation.alias(), privateKeyAnnotation.password());

              if (Signer.class.equals(pair.key().getType())) {
                final var signer =
                    signer(
                        privateKey,
                        signerAnnotation.algorithm(),
                        signerAnnotation.provider(),
                        Charset.forName(signerAnnotation.charset()),
                        signerAnnotation.encoding());
                set(pair.key(), object, signer);
              }
            });
  }

  private static void instrumentVerifiers(final List<Field> fields, final Object object) {
    fields.stream()
        .filter(
            field -> field.isAnnotationPresent(com.mirkocaserta.bruce.annotations.Verifier.class))
        .map(
            field ->
                Pair.of(
                    field,
                    field.getDeclaredAnnotation(com.mirkocaserta.bruce.annotations.Verifier.class)))
        .forEach(
            pair -> {
              pair.key().setAccessible(true);
              final var verifierAnnotation = pair.val();
              final var publicKeyAnnotation = verifierAnnotation.publicKey();
              final var keyStoreAnnotation = publicKeyAnnotation.keystore();
              final var keystore =
                  keystore(
                      keyStoreAnnotation.location(),
                      keyStoreAnnotation.password(),
                      keyStoreAnnotation.type(),
                      keyStoreAnnotation.provider());
              final var publicKey = publicKey(keystore, publicKeyAnnotation.alias());

              if (Verifier.class.equals(pair.key().getType())) {
                final var verifier =
                    verifier(
                        publicKey,
                        verifierAnnotation.algorithm(),
                        verifierAnnotation.provider(),
                        Charset.forName(verifierAnnotation.charset()),
                        verifierAnnotation.encoding());
                set(pair.key(), object, verifier);
              }
            });
  }

  private static void instrumentDigesters(final List<Field> fields, final Object object) {
    fields.stream()
        .filter(
            field -> field.isAnnotationPresent(com.mirkocaserta.bruce.annotations.Digester.class))
        .map(
            field ->
                Pair.of(
                    field,
                    field.getDeclaredAnnotation(com.mirkocaserta.bruce.annotations.Digester.class)))
        .forEach(
            pair -> {
              pair.key().setAccessible(true);

              if (Digester.class.equals(pair.key().getType())) {
                final var digester =
                    digester(
                        pair.val().algorithm(),
                        pair.val().provider(),
                        pair.val().encoding(),
                        Charset.forName(pair.val().charsetName()));
                set(pair.key(), object, digester);
              }
            });
  }

  private static void set(final Field field, final Object instance, final Object fieldValue) {
    try {
      field.set(instance, fieldValue);
    } catch (IllegalAccessException e) {
      throw new BruceException(
          String.format(
              "could not instrument field: %s.%s",
              instance.getClass().getSimpleName(), field.getName()),
          e);
    }
  }
}
