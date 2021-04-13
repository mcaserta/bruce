package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipherer;
import com.mirkocaserta.bruce.cipher.symmetric.CiphererByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCiphererByKey;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.EncodingDigester;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.*;
import com.mirkocaserta.bruce.util.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * <p>This class is the main entrypoint for all cryptographic operations.</p>
 *
 * <p>Just type <code>Bruce.</code> in your IDE and let autocompletion do
 * the rest.</p>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public class Bruce {

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

    private static final ConcurrentMap<String, com.mirkocaserta.bruce.cipher.asymmetric.Cipherer> ciphererCache = new ConcurrentHashMap<>();

    private Bruce() {
        // utility class, users can't make new instances
    }

    /**
     * Returns the default keystore using configuration from the following
     * system properties:
     *
     * <ul>
     *   <li><code>javax.net.ssl.keyStore</code></li>
     *   <li><code>javax.net.ssl.keyStorePassword</code></li>
     * </ul>
     * <p>
     * The keystore location supports the following protocols:
     *
     * <ul>
     *   <li><code>classpath:</code></li>
     *   <li><code>http:</code></li>
     *   <li><code>https:</code></li>
     *   <li><code>file:</code></li>
     * </ul>
     * <p>
     * If no protocol is specified, <code>file</code> is assumed.
     * <p>
     * The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
     *
     * @return the default keystore
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore() {
        return keystore(DEFAULT_KEYSTORE_TYPE);
    }

    /**
     * Returns the default keystore using configuration from the following
     * system properties:
     *
     * <ul>
     *   <li><code>javax.net.ssl.keyStore</code></li>
     *   <li><code>javax.net.ssl.keyStorePassword</code></li>
     * </ul>
     * <p>
     * The keystore location supports the following protocols:
     *
     * <ul>
     *   <li><code>classpath:</code></li>
     *   <li><code>http:</code></li>
     *   <li><code>https:</code></li>
     *   <li><code>file:</code></li>
     * </ul>
     * <p>
     * If no protocol is specified, <code>file</code> is assumed.
     *
     * @param type the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @return the default keystore
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String type) {
        final String location = System.getProperty("javax.net.ssl.keyStore");

        if (location == null || location.isBlank()) {
            throw new BruceException("no value was specified for the system property: javax.net.ssl.keyStore");
        }

        return keystore(location, System.getProperty("javax.net.ssl.keyStorePassword"), type);
    }

    /**
     * Returns a key store. The default keystore type is {@value #DEFAULT_KEYSTORE_TYPE}.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, String password) {
        return keystore(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
    }

    /**
     * Returns a key store.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @param type     the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, String password, String type) {
        return keystore(location, password, type, BLANK);
    }

    /**
     * Returns a key store.
     *
     * @param location the keystore location. The following protocols are supported:
     *                 <ul>
     *                 <li><code>classpath:</code></li>
     *                 <li><code>http:</code></li>
     *                 <li><code>https:</code></li>
     *                 <li><code>file:</code></li>
     *                 </ul>
     *                 If no protocol is specified, <code>file</code> is assumed.
     * @param password the password
     * @param type     the keystore type (ex: <code>JKS</code>, <code>PKCS12</code>)
     * @param provider the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a key store
     * @throws BruceException on loading errors
     */
    public static KeyStore keystore(String location, String password, String type, String provider) {
        try {
            final KeyStore keyStore;
            if (provider == null || provider.isBlank()) {
                keyStore = KeyStore.getInstance(type);
            } else {
                keyStore = KeyStore.getInstance(type, provider);
            }
            final InputStream inputStream;
            if (location.startsWith("classpath:")) {
                inputStream = Bruce.class.getResourceAsStream(location.replaceFirst("classpath:", BLANK));
            } else if (location.matches("^https*://.*$")) {
                inputStream = new URL(location).openConnection().getInputStream();
            } else {
                inputStream = Files.newInputStream(Path.of(location.replaceFirst("file:", BLANK)));
            }
            keyStore.load(inputStream, password.toCharArray());
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new BruceException(String.format("error loading keystore: location=%s", location), e);
        } catch (NoSuchProviderException e) {
            throw new BruceException(String.format("error loading keystore, no such provider: provider=%s", provider), e);
        }
    }

    /**
     * Loads a certificate from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the certificate alias
     * @return the certificate
     * @throws BruceException on loading errors
     */
    public static Certificate certificate(KeyStore keystore, String alias) {
        try {
            final Certificate certificate = keystore.getCertificate(alias);

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
     * @param alias    the certificate alias
     * @return the public key
     * @throws BruceException on loading errors
     */
    public static PublicKey publicKey(KeyStore keystore, String alias) {
        try {
            final Certificate certificate = keystore.getCertificate(alias);

            if (certificate == null) {
                throw new BruceException(String.format("certificate not found for alias: %s", alias));
            }

            return certificate.getPublicKey();
        } catch (KeyStoreException e) {
            throw new BruceException(String.format("error loading public key with alias: %s", alias), e);
        }
    }

    /**
     * Loads a private key from the given keystore.
     *
     * @param keystore the keystore to read from
     * @param alias    the certificate alias
     * @param password the private key password
     * @return the private key
     * @throws BruceException on loading errors
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, String password) {
        try {
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));

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
     * @param alias    the secret key alias
     * @param password the secret key password
     * @return the secret key
     * @throws BruceException on loading errors
     */
    public static Key secretKey(KeyStore keystore, String alias, String password) {
        try {
            final Key key = keystore.getKey(alias, password.toCharArray());

            if (key == null) {
                throw new BruceException(String.format("no such secret key with alias: %s", alias));
            }

            return key;
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new BruceException(String.format("error loading secret key with alias: %s", alias), e);
        }
    }

    /**
     * Returns an encoding message digester for the given algorithm.
     * <p>
     * This digester implementation assumes your input messages
     * are using the <code>UTF-8</code> charset.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param encoding  the encoding
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, Encoding encoding) {
        return digester(algorithm, BLANK, encoding, UTF_8);
    }

    /**
     * Returns an encoding message digester for the given algorithm and provider.
     * <p>
     * This digester implementation assumes your input messages
     * are using the <code>UTF-8</code> charset.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the encoding
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, String provider, Encoding encoding) {
        return digester(algorithm, provider, encoding, UTF_8);
    }

    /**
     * Returns an encoding message digester for the given algorithm and provider.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the encoding
     * @param charset   the charset used for the input messages
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, String provider, Encoding encoding, Charset charset) {
        if (encoding == null) {
            throw new BruceException(INVALID_ENCODING_NULL);
        }

        final Digester rawDigester = provider == null || provider.isBlank()
                ? digester(algorithm)
                : digester(algorithm, provider);

        return message -> encode(encoding, rawDigester.digest(message.getBytes(charset)));
    }

    /**
     * Returns a raw byte array message digester for the given algorithm and provider.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a raw byte array message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Digester digester(String algorithm, String provider) {
        final MessageDigest digester;

        try {
            digester = provider == null || provider.isBlank()
                    ? MessageDigest.getInstance(algorithm)
                    : MessageDigest.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
        } catch (NoSuchProviderException e) {
            throw new BruceException(String.format("No such provider: %s", provider), e);
        }

        return digester::digest;
    }

    /**
     * Returns a raw byte array message digester for the given algorithm.
     *
     * @param algorithm the algorithm (ex: SHA1, MD5, etc)
     * @return a raw byte array message digester
     * @throws BruceException on no such algorithm exception
     */
    public static Digester digester(String algorithm) {
        return digester(algorithm, BLANK);
    }

    /**
     * Returns a signer for the given private key and
     * algorithm.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @return the signer
     */
    public static Signer signer(PrivateKey privateKey, String algorithm) {
        return signer(privateKey, algorithm, BLANK);
    }

    /**
     * Returns a signer for the given private key,
     * algorithm and provider.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param provider   the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the signer
     */
    public static Signer signer(PrivateKey privateKey, String algorithm, String provider) {
        return message -> {
            try {
                final Signature signature =
                        provider == null || provider.isBlank()
                                ? Signature.getInstance(algorithm)
                                : Signature.getInstance(algorithm, provider);
                signature.initSign(privateKey);
                signature.update(message);
                return signature.sign();
            } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
                throw new BruceException(String.format("error generating the signature: algorithm=%s, provider=%s", algorithm, provider), e);
            }
        };
    }

    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return signer(privateKeyMap, algorithm, BLANK);
    }

    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return (privateKeyId, message) -> {
            PrivateKey privateKey = privateKeyMap.get(privateKeyId);

            if (privateKey == null) {
                throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
            }

            return signer(privateKey, algorithm, provider).sign(message);
        };
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Encoding encoding) {
        return signer(privateKey, algorithm, BLANK, UTF_8, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Charset charset, Encoding encoding) {
        return signer(privateKey, algorithm, BLANK, charset, encoding);
    }

    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, String provider, Charset charset, Encoding encoding) {
        if (encoding == null) {
            throw new BruceException(INVALID_ENCODING_NULL);
        }

        if (charset == null) {
            throw new BruceException("Invalid charset: null");
        }

        final Signer signer = signer(privateKey, algorithm, provider);
        return message -> encode(encoding, signer.sign(message.getBytes(charset)));
    }

    public static Verifier verifier(PublicKey publicKey, String algorithm) {
        return verifier(publicKey, algorithm, BLANK);
    }

    public static Verifier verifier(PublicKey publicKey, String algorithm, String provider) {
        return (message, signature) -> {
            try {
                final Signature signatureInstance =
                        provider == null || provider.isBlank()
                                ? Signature.getInstance(algorithm)
                                : Signature.getInstance(algorithm, provider);
                signatureInstance.initVerify(publicKey);
                signatureInstance.update(message);
                return signatureInstance.verify(signature);
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
                throw new BruceException(String.format("error verifying the signature: algorithm=%s, provider=%s", algorithm, provider), e);
            } catch (SignatureException e) {
                return false;
            }
        };
    }

    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return verifier(publicKeyMap, algorithm, BLANK);
    }

    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return (publicKeyId, message, signature) -> {
            PublicKey publicKey = publicKeyMap.get(publicKeyId);

            if (publicKey == null) {
                throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
            }

            return verifier(publicKey, algorithm, provider).verify(message, signature);
        };
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, Encoding encoding) {
        return verifier(publicKey, algorithm, BLANK, encoding);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Encoding encoding) {
        return verifier(publicKey, algorithm, provider, UTF_8, encoding);
    }

    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Charset charset, Encoding encoding) {
        if (encoding == null) {
            throw new BruceException(INVALID_ENCODING_NULL);
        }

        if (charset == null) {
            throw new BruceException("Invalid charset: null");
        }

        final Verifier verifier = verifier(publicKey, algorithm, provider);
        return (message, signature) -> verifier.verify(message.getBytes(charset), decode(encoding, signature));
    }

    public static byte[] symmetricKey(String algorithm) {
        return symmetricKey(algorithm, BLANK);
    }

    public static byte[] symmetricKey(String algorithm, String provider) {
        try {
            final KeyGenerator generator = provider == null || provider.isBlank()
                    ? KeyGenerator.getInstance(algorithm)
                    : KeyGenerator.getInstance(algorithm, provider);
            generator.init(new SecureRandom());
            return generator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new BruceException(String.format("cannot generate key: algorithm=%s, provider=%s", algorithm, provider), e);
        }
    }

    public static String symmetricKey(String algorithm, Encoding encoding) {
        return symmetricKey(algorithm, BLANK, encoding);
    }

    public static String symmetricKey(String algorithm, String provider, Encoding encoding) {
        return encode(encoding, symmetricKey(algorithm, provider));
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.CiphererByKey cipherer(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return cipherer(keyAlgorithm, cipherAlgorithm, BLANK, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.CiphererByKey cipherer(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return (key, iv, message) -> {
            try {
                final IvParameterSpec initializationVectorSpec = new IvParameterSpec(iv);
                final SecretKeySpec spec = new SecretKeySpec(key, keyAlgorithm);
                final Cipher cipher = provider == null || provider.isBlank()
                        ? Cipher.getInstance(cipherAlgorithm)
                        : Cipher.getInstance(cipherAlgorithm, provider);
                switch (mode) {
                    case ENCRYPT:
                        cipher.init(Cipher.ENCRYPT_MODE, spec, initializationVectorSpec);
                        break;
                    case DECRYPT:
                        cipher.init(Cipher.DECRYPT_MODE, spec, initializationVectorSpec);
                        break;
                    default:
                        throw new BruceException(String.format("error encrypting/decrypting message: invalid mode; mode=%s", mode));
                }
                return cipher.doFinal(message);
            } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IllegalBlockSizeException e) {
                throw new BruceException("error encrypting/decrypting message", e);
            }
        };
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.Cipherer cipherer(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return cipherer(key, keyAlgorithm, cipherAlgorithm, BLANK, mode);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.Cipherer cipherer(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        final CiphererByKey cipherer = cipherer(keyAlgorithm, cipherAlgorithm, provider, mode);
        return (iv, message) -> cipherer.encrypt(key, iv, message);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCiphererByKey ciphererByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
        return ciphererByKey(keyAlgorithm, cipherAlgorithm, BLANK, mode, charset);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCiphererByKey ciphererByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
        final CiphererByKey cipherer = cipherer(keyAlgorithm, cipherAlgorithm, provider, mode);

        return (key, iv, message, encoding) -> {
            final byte[] keyBA = decode(encoding, key);
            final byte[] ivBA = decode(encoding, iv);

            switch (mode) {
                case ENCRYPT:
                    return encode(encoding, cipherer.encrypt(keyBA, ivBA, message.getBytes(charset)));
                case DECRYPT:
                    return new String(cipherer.encrypt(keyBA, ivBA, decode(encoding, message)), charset);
                default:
                    throw new BruceException(String.format("unsupported mode: %s", mode));
            }
        };
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherer cipherer(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Encoding encoding) {
        return cipherer(key, keyAlgorithm, cipherAlgorithm, BLANK, mode, charset, encoding);
    }

    public static com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherer cipherer(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Encoding encoding) {
        final EncodingCiphererByKey cipherer = ciphererByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
        return (iv, message) -> cipherer.encrypt(key, iv, message, encoding);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.Cipherer cipherer(Key key, String algorithm, Mode mode) {
        return cipherer(key, algorithm, BLANK, mode);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.Cipherer cipherer(Key key, String algorithm, String provider, Mode mode) {
        return message -> {
            try {
                final Cipher cipher = provider == null || provider.isBlank()
                        ? Cipher.getInstance(algorithm)
                        : Cipher.getInstance(algorithm, provider);
                switch (mode) {
                    case ENCRYPT:
                        cipher.init(Cipher.ENCRYPT_MODE, key);
                        break;
                    case DECRYPT:
                        cipher.init(Cipher.DECRYPT_MODE, key);
                        break;
                    default:
                        throw new BruceException(String.format("error encrypting/decrypting message: invalid mode; mode=%s", mode));
                }
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new BruceException(String.format("error encrypting/decrypting message; mode=%s", mode), e);
            }
        };
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.CiphererByKey cipherer(Map<String, Key> keys, String algorithm) {
        return cipherer(keys, algorithm, BLANK);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.CiphererByKey cipherer(Map<String, Key> keys, String algorithm, String provider) {
        // we use a cipherer cache here as getting a new one each time is a bit expensive
        return (keyId, mode, message) -> getCipherer(keys, keyId, algorithm, provider, mode).encrypt(message);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherer cipherer(Key key, String algorithm, Mode mode, Encoding encoding, Charset charset) {
        return cipherer(key, algorithm, BLANK, mode, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherer cipherer(Key key, String algorithm, String provider, Mode mode, Encoding encoding, Charset charset) {
        final Cipherer cipherer = cipherer(key, algorithm, provider, mode);
        return message -> crypt(cipherer, message, mode, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCiphererByKey cipherer(Map<String, Key> keys, String algorithm, Encoding encoding, Charset charset) {
        return cipherer(keys, algorithm, BLANK, encoding, charset);
    }

    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCiphererByKey cipherer(Map<String, Key> keys, String algorithm, String provider, Encoding encoding, Charset charset) {
        return (keyId, mode, message) -> {
            final Cipherer cipherer = getCipherer(keys, keyId, algorithm, provider, mode);
            return crypt(cipherer, message, mode, encoding, charset);
        };
    }

    public static com.mirkocaserta.bruce.mac.Mac mac(Key key, String algorithm) {
        return mac(key, algorithm, BLANK);
    }

    public static com.mirkocaserta.bruce.mac.Mac mac(Key key, String algorithm, String provider) {
        return message -> {
            try {
                final javax.crypto.Mac mac = provider == null || provider.isBlank()
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

    public static com.mirkocaserta.bruce.mac.EncodingMac mac(Key key, String algorithm, Encoding encoding, Charset charset) {
        return mac(key, algorithm, BLANK, encoding, charset);
    }

    public static com.mirkocaserta.bruce.mac.EncodingMac mac(Key key, String algorithm, String provider, Encoding encoding, Charset charset) {
        final com.mirkocaserta.bruce.mac.Mac mac = mac(key, algorithm, provider);
        return message -> encode(encoding, mac.get(message.getBytes(charset)));
    }

    private static String crypt(Cipherer cipherer, String message, Mode mode, Encoding encoding, Charset charset) {
        switch (mode) {
            case ENCRYPT:
                return encode(encoding, cipherer.encrypt(message.getBytes(charset)));
            case DECRYPT:
                return new String(cipherer.encrypt(decode(encoding, message)), charset);
            default:
                throw new BruceException(String.format("unsupported mode: %s", mode));
        }
    }

    private static Cipherer getCipherer(Map<String, Key> keys, String keyId, String algorithm, String provider, Mode mode) {
        return ciphererCache.computeIfAbsent(ciphererCacheKey(keyId, algorithm, provider, mode), ignored -> {
            final Key key = keys.get(keyId);
            if (key == null) {
                throw new BruceException(String.format("no such key: %s", keyId));
            }
            return cipherer(key, algorithm, provider, mode);
        });
    }

    private static String ciphererCacheKey(String keyId, String algorithm, String provider, Mode mode) {
        return keyId + "::" + algorithm + "::" + provider + "::" + mode;
    }

    private static byte[] decode(final Encoding encoding, final String input) {
        try {
            switch (encoding) {
                case HEX:
                    return HEX_DECODER.decode(input);
                case BASE64:
                    return BASE_64_DECODER.decode(input);
                case URL:
                    return URL_DECODER.decode(input);
                case MIME:
                    return MIME_DECODER.decode(input);
                default:
                    throw new BruceException(String.format("unsupported encoding: %s", encoding));
            }
        } catch (IllegalArgumentException e) {
            throw new BruceException(String.format("invalid input: encoding=%s, input=%s", encoding, input));
        }
    }

    private static String encode(final Encoding encoding, final byte[] input) {
        switch (encoding) {
            case HEX:
                return HEX_ENCODER.encodeToString(input);
            case BASE64:
                return BASE_64_ENCODER.encodeToString(input);
            case URL:
                return URL_ENCODER.encodeToString(input);
            case MIME:
                return MIME_ENCODER.encodeToString(input);
            default:
                throw new BruceException(String.format("unsupported encoding: %s", encoding));
        }
    }

    public enum Encoding {
        HEX, BASE64, URL, MIME
    }

}
