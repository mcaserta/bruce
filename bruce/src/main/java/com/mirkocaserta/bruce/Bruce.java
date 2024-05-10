package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.api.Digester;
import com.mirkocaserta.bruce.api.KeyStore;
import com.mirkocaserta.bruce.certificate.CertificateImpl;
import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipher;
import com.mirkocaserta.bruce.cipher.symmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.digest.DigesterImpl;
import com.mirkocaserta.bruce.keys.PrivateKeyImpl;
import com.mirkocaserta.bruce.keys.PublicKeyImpl;
import com.mirkocaserta.bruce.keystore.KeyStoreImpl;
import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;
import com.mirkocaserta.bruce.signature.*;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.util.Hex;
import com.mirkocaserta.bruce.util.Pair;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.security.*;
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

  public static final Digester digester = new DigesterImpl();
  public static final KeyStore keystore = new KeyStoreImpl();
  public static final com.mirkocaserta.bruce.api.Certificate certificate = new CertificateImpl();
  public static final com.mirkocaserta.bruce.api.PublicKey publicKey = new PublicKeyImpl();
  public static final com.mirkocaserta.bruce.api.PrivateKey privateKey = new PrivateKeyImpl();

  private static final String BLANK = "";
  private static final String INVALID_ENCODING_NULL = "Invalid encoding: null";
  private static final Hex.Encoder HEX_ENCODER = Hex.getEncoder();
  private static final Base64.Encoder BASE_64_ENCODER = Base64.getEncoder();
  private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder();
  private static final Base64.Encoder MIME_ENCODER = Base64.getMimeEncoder();
  private static final Hex.Decoder HEX_DECODER = Hex.getDecoder();
  private static final Base64.Decoder BASE_64_DECODER = Base64.getDecoder();
  private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
  private static final Base64.Decoder MIME_DECODER = Base64.getMimeDecoder();
  private static final String MODE_CANNOT_BE_NULL = "Mode cannot be null";
  private static final ConcurrentMap<String, Cipher> cipherCache = new ConcurrentHashMap<>();

  private Bruce() {
    // utility class, users can't make new instances
  }

  /**
   * Loads a secret key from the given with.
   *
   * @param keystore the with to read from
   * @param alias the secret key alias
   * @param password the secret key password
   * @return the secret key
   * @throws BruceException on loading errors
   */
  public static Key secretKey(
      final java.security.KeyStore keystore, final String alias, final char[] password) {
    try {
      final var key = keystore.getKey(alias, password);

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
  public static KeyPair keyPair(final String algorithm, final int keySize) {
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
  public static KeyPair keyPair(final String algorithm, final String provider, final int keySize) {
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
  public static KeyPair keyPair(
      final String algorithm, final int keySize, final SecureRandom random) {
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
      final String algorithm, final String provider, final int keySize, final SecureRandom random) {
    try {
      final var keyGen =
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
   * Returns a signer for the given private key and algorithm.
   *
   * @param privateKey the signing key
   * @param algorithm the signing algorithm
   * @return the signer
   * @throws BruceException on no such algorithm or provider exceptions
   */
  public static Signer signer(final PrivateKey privateKey, final String algorithm) {
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
  public static Signer signer(
      final PrivateKey privateKey, final String algorithm, final String provider) {
    final var signer =
        new Signer() {
          @Override
          public byte[] sign(byte[] message) {
            try {
              final var signature = getSignature(algorithm, provider);
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

  private static Signature getSignature(final String algorithm, final String provider) {
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
  public static SignerByKey signer(
      final Map<String, PrivateKey> privateKeyMap, final String algorithm) {
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
      final Map<String, PrivateKey> privateKeyMap, final String algorithm, final String provider) {
    return (privateKeyId, message) -> {
      final var privateKey = privateKeyMap.get(privateKeyId);

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
      final Map<String, PrivateKey> privateKeyMap,
      final String algorithm,
      final Encoding encoding) {
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
      final Map<String, PrivateKey> privateKeyMap,
      final String algorithm,
      final Charset charset,
      final Encoding encoding) {
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
      final Map<String, PrivateKey> privateKeyMap,
      final String algorithm,
      final String provider,
      final Charset charset,
      final Encoding encoding) {
    return (privateKeyId, message) -> {
      final var privateKey = privateKeyMap.get(privateKeyId);

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
  public static Signer signer(
      final PrivateKey privateKey, final String algorithm, final Encoding encoding) {
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
      final PrivateKey privateKey,
      final String algorithm,
      final Charset charset,
      final Encoding encoding) {
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
      final PrivateKey privateKey,
      final String algorithm,
      final String provider,
      final Charset charset,
      final Encoding encoding) {
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
  public static Verifier verifier(final PublicKey publicKey, final String algorithm) {
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
  public static Verifier verifier(
      final PublicKey publicKey, final String algorithm, final String provider) {
    return new Verifier() {
      @Override
      public boolean verify(byte[] message, byte[] signature) {
        try {
          final var signatureInstance = getSignature(algorithm, provider);
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
  public static VerifierByKey verifier(
      final Map<String, PublicKey> publicKeyMap, final String algorithm) {
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
      final Map<String, PublicKey> publicKeyMap, final String algorithm, final String provider) {
    return (publicKeyId, message, signature) -> {
      final var publicKey = publicKeyMap.get(publicKeyId);

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
  public static Verifier verifier(
      final PublicKey publicKey, final String algorithm, final Encoding encoding) {
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
      final PublicKey publicKey,
      final String algorithm,
      final String provider,
      final Encoding encoding) {
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
      final PublicKey publicKey,
      final String algorithm,
      final String provider,
      final Charset charset,
      final Encoding encoding) {
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
      final Map<String, PublicKey> publicKeyMap, final String algorithm, final Encoding encoding) {
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
      final Map<String, PublicKey> publicKeyMap,
      final String algorithm,
      final Charset charset,
      final Encoding encoding) {
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
      final Map<String, PublicKey> publicKeyMap,
      final String algorithm,
      final String provider,
      final Charset charset,
      final Encoding encoding) {
    return (publicKeyId, message, signature) -> {
      final var publicKey = publicKeyMap.get(publicKeyId);

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
  public static byte[] symmetricKey(final String algorithm) {
    return symmetricKey(algorithm, BLANK);
  }

  /**
   * Generates a symmetric key using the specified algorithm and provider.
   *
   * @param algorithm the key algorithm
   * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
   * @return a newly generated symmetric key
   */
  public static byte[] symmetricKey(final String algorithm, final String provider) {
    try {
      final var generator =
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
  public static String symmetricKey(final String algorithm, final Encoding encoding) {
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
  public static String symmetricKey(
      final String algorithm, final String provider, final Encoding encoding) {
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
  public static CipherByKey cipher(
      final String keyAlgorithm, final String cipherAlgorithm, final Mode mode) {
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
      final String keyAlgorithm,
      final String cipherAlgorithm,
      final String provider,
      final Mode mode) {
    if (mode == null) {
      throw new BruceException(MODE_CANNOT_BE_NULL);
    }

    return (key, iv, message) -> {
      try {
        final var initializationVectorSpec = new IvParameterSpec(iv);
        final var spec = new SecretKeySpec(key, keyAlgorithm);
        final var cipher =
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
      final byte[] key, final String keyAlgorithm, final String cipherAlgorithm, final Mode mode) {
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
      final byte[] key,
      final String keyAlgorithm,
      final String cipherAlgorithm,
      final String provider,
      final Mode mode) {
    final var cipher = cipher(keyAlgorithm, cipherAlgorithm, provider, mode);
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
      final String keyAlgorithm,
      final String cipherAlgorithm,
      final Mode mode,
      final Charset charset) {
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
      final String keyAlgorithm,
      final String cipherAlgorithm,
      final String provider,
      final Mode mode,
      final Charset charset) {
    final var cipher = cipher(keyAlgorithm, cipherAlgorithm, provider, mode);

    return (key, iv, message, encoding) -> {
      final var keyBA = decode(encoding, key);
      final var ivBA = decode(encoding, iv);

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
      final String key,
      final String keyAlgorithm,
      final String cipherAlgorithm,
      final Mode mode,
      final Charset charset,
      final Encoding encoding) {
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
      final String key,
      final String keyAlgorithm,
      final String cipherAlgorithm,
      final String provider,
      final Mode mode,
      final Charset charset,
      final Encoding encoding) {
    final var cipher = cipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
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
  public static Cipher cipher(final Key key, final String algorithm, final Mode mode) {
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
  public static Cipher cipher(
      final Key key, final String algorithm, final String provider, final Mode mode) {
    if (mode == null) {
      throw new BruceException(MODE_CANNOT_BE_NULL);
    }

    return message -> {
      try {
        final var cipher =
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
      final Map<String, Key> keys, final String algorithm) {
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
      final Map<String, Key> keys, final String algorithm, final String provider) {
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
      final Key key,
      final String algorithm,
      final Mode mode,
      final Encoding encoding,
      final Charset charset) {
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
      final Key key,
      final String algorithm,
      final String provider,
      final Mode mode,
      final Encoding encoding,
      final Charset charset) {
    final var cipher = cipher(key, algorithm, provider, mode);
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
      final Map<String, Key> keys,
      final String algorithm,
      final Encoding encoding,
      final Charset charset) {
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
      final Map<String, Key> keys,
      final String algorithm,
      final String provider,
      final Encoding encoding,
      final Charset charset) {
    return (keyId, mode, message) -> {
      final var cipher = getCipher(keys, keyId, algorithm, provider, mode);
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
      final Cipher cipher,
      final String message,
      final Mode mode,
      final Encoding encoding,
      final Charset charset) {
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
      final Map<String, Key> keys,
      final String keyId,
      final String algorithm,
      final String provider,
      final Mode mode) {
    return cipherCache.computeIfAbsent(
        cipherCacheKey(keyId, algorithm, provider, mode),
        ignored -> {
          final var key = keys.get(keyId);
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
  private static String cipherCacheKey(
      final String keyId, final String algorithm, final String provider, final Mode mode) {
    return keyId + "::" + algorithm + "::" + provider + "::" + mode;
  }

  /**
   * Returns an interface for producing message authentication codes.
   *
   * @param key the secret key for digesting the messages
   * @param algorithm the signature algorithm
   * @return the message authentication codes interface
   */
  public static Mac mac(final Key key, final String algorithm) {
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
  public static Mac mac(final Key key, final String algorithm, final String provider) {
    return message -> {
      try {
        final var mac =
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
  public static EncodingMac mac(
      final Key key, final String algorithm, final Encoding encoding, final Charset charset) {
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
      final Key key,
      final String algorithm,
      final String provider,
      final Encoding encoding,
      final Charset charset) {
    final var mac = mac(key, algorithm, provider);
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
  public static byte[] decode(final Encoding encoding, final String input) {
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
  public static String encode(final Encoding encoding, final byte[] input) {
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
        .filter(
            field -> field.isAnnotationPresent(com.mirkocaserta.bruce.api.annotations.Signer.class))
        .map(
            field ->
                Pair.of(
                    field,
                    field.getDeclaredAnnotation(
                        com.mirkocaserta.bruce.api.annotations.Signer.class)))
        .forEach(
            pair -> {
              pair.key().setAccessible(true);
              final var signerAnnotation = pair.val();
              final var privateKeyAnnotation = signerAnnotation.privateKey();
              final var keyStoreAnnotation = privateKeyAnnotation.keystore();
              final var keystore =
                  Bruce.keystore.with(
                      keyStoreAnnotation.location(),
                      keyStoreAnnotation.password(),
                      keyStoreAnnotation.type(),
                      keyStoreAnnotation.provider());
              final var privateKey =
                  Bruce.privateKey.with(
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
            field ->
                field.isAnnotationPresent(com.mirkocaserta.bruce.api.annotations.Verifier.class))
        .map(
            field ->
                Pair.of(
                    field,
                    field.getDeclaredAnnotation(
                        com.mirkocaserta.bruce.api.annotations.Verifier.class)))
        .forEach(
            pair -> {
              pair.key().setAccessible(true);
              final var verifierAnnotation = pair.val();
              final var publicKeyAnnotation = verifierAnnotation.publicKey();
              final var keyStoreAnnotation = publicKeyAnnotation.keystore();
              final var keystore =
                  Bruce.keystore.with(
                      keyStoreAnnotation.location(),
                      keyStoreAnnotation.password(),
                      keyStoreAnnotation.type(),
                      keyStoreAnnotation.provider());
              final var publicKey = Bruce.publicKey.with(keystore, publicKeyAnnotation.alias());

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
            field ->
                field.isAnnotationPresent(com.mirkocaserta.bruce.api.annotations.Digester.class))
        .map(
            field ->
                Pair.of(
                    field,
                    field.getDeclaredAnnotation(
                        com.mirkocaserta.bruce.api.annotations.Digester.class)))
        .forEach(
            pair -> {
              pair.key().setAccessible(true);

              final var digester =
                  Bruce.digester.with(
                      pair.val().algorithm(),
                      pair.val().provider(),
                      pair.val().encoding(),
                      Charset.forName(pair.val().charsetName()),
                      pair.val().outputType());
              set(pair.key(), object, digester);
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
