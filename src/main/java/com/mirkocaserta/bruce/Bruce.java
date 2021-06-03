package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.cipher.Mode;
import com.mirkocaserta.bruce.cipher.asymmetric.Cipher;
import com.mirkocaserta.bruce.cipher.symmetric.CipherByKey;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipher;
import com.mirkocaserta.bruce.cipher.symmetric.EncodingCipherByKey;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.EncodingDigester;
import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;
import com.mirkocaserta.bruce.signature.Signer;
import com.mirkocaserta.bruce.signature.*;
import com.mirkocaserta.bruce.util.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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

    /**
     * The default keystore format/type.
     */
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

    private static final ConcurrentMap<String, Cipher> cipherCache = new ConcurrentHashMap<>();

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
        return keystore(
                System.getProperty("javax.net.ssl.keyStore"),
                System.getProperty("javax.net.ssl.keyStorePassword"),
                type
        );
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
        return keystore(location, password, DEFAULT_KEYSTORE_TYPE, "SUN");
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
        return keystore(location, password, type, "SUN");
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
        if (location == null || location.isBlank()) {
            throw new BruceException("please provide a valid key store location");
        }

        try {
            final KeyStore keyStore = KeyStore.getInstance(type, provider);
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
        } catch (Exception e) {
            throw new BruceException("error loading keystore", e);
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
        return certificate(keystore, alias).getPublicKey();
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
     * Generates a key pair.
     *
     * @param algorithm the key algorithm
     * @param keySize   the key size
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize) {
        return keyPair(algorithm, null, keySize, null);
    }

    /**
     * Generates a key pair.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param keySize   the key size
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize) {
        return keyPair(algorithm, provider, keySize, null);
    }

    /**
     * Generates a key pair with the specified random number generator.
     *
     * @param algorithm the key algorithm
     * @param keySize   the key size
     * @param random    the random number generator
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
        return keyPair(algorithm, null, keySize, random);
    }

    /**
     * Generates a key pair with the specified provider and random number generator.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param keySize   the key size
     * @param random    the random number generator
     * @return the key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        try {
            KeyPairGenerator keyGen = provider == null || provider.isBlank() ?
                    KeyPairGenerator.getInstance(algorithm) :
                    KeyPairGenerator.getInstance(algorithm, provider);

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
     * Returns an encoding message digester for the given algorithm and character set.
     *
     * @param algorithm the algorithm (ex: <code>SHA1</code>, <code>MD5</code>, etc)
     * @param encoding  the encoding
     * @param charset   the charset used for the input messages
     * @return an encoding message digester
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static EncodingDigester digester(String algorithm, Encoding encoding, Charset charset) {
        return digester(algorithm, BLANK, encoding, charset);
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
     * @throws BruceException on no such algorithm or provider exceptions
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
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Signer signer(PrivateKey privateKey, String algorithm, String provider) {
        final Signer signer = message -> {
            try {
                final Signature signature = getSignature(algorithm, provider);
                signature.initSign(privateKey);
                signature.update(message);
                return signature.sign();
            } catch (SignatureException | InvalidKeyException e) {
                throw new BruceException(String.format("error generating the signature: algorithm=%s, provider=%s", algorithm, provider), e);
            }
        };

        /*
        This is here so we can trigger exceptions at initialization time
        rather then at runtime when invoking the sign method on the signer.
         */
        signer.sign("FAIL FAST".getBytes(UTF_8));
        return signer;
    }

    private static Signature getSignature(String algorithm, String provider) {
        try {
            return provider == null || provider.isBlank()
                    ? Signature.getInstance(algorithm)
                    : Signature.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new BruceException(String.format("error getting signer: algorithm=%s, provider=%s", algorithm, provider), e);
        }
    }

    /**
     * Returns a signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm) {
        return signer(privateKeyMap, algorithm, BLANK);
    }

    /**
     * Returns a signer where the private key can be chosen at runtime.
     * The signing keys must be provided in a map where the map key is an
     * alias to the signing key and the value is the corresponding signing key.
     *
     * @param privateKeyMap the signing key map
     * @param algorithm     the signing algorithm
     * @param provider      the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the signer
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm, String provider) {
        return (privateKeyId, message) -> {
            PrivateKey privateKey = privateKeyMap.get(privateKeyId);

            if (privateKey == null) {
                throw new BruceException(String.format("private key not found for id: %s", privateKeyId));
            }

            return signer(privateKey, algorithm, provider).sign(message);
        };
    }

    /**
     * Returns an encoding signer for the given private key using the
     * default provider and {@link StandardCharsets#UTF_8}
     * as the default charset used in messages.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param encoding   the signature encoding
     * @return the signer
     * @throws BruceException on initialization exceptions
     */
    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Encoding encoding) {
        return signer(privateKey, algorithm, BLANK, UTF_8, encoding);
    }

    /**
     * Returns an encoding signer for the given private key using the
     * default provider.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param charset    the charset used in messages
     * @param encoding   the signature encoding
     * @return the signer
     * @throws BruceException on initialization exceptions
     */
    public static EncodingSigner signer(PrivateKey privateKey, String algorithm, Charset charset, Encoding encoding) {
        return signer(privateKey, algorithm, BLANK, charset, encoding);
    }

    /**
     * Returns an encoding signer for the given private key.
     *
     * @param privateKey the signing key
     * @param algorithm  the signing algorithm
     * @param provider   the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param charset    the charset used in messages
     * @param encoding   the signature encoding
     * @return the signer
     * @throws BruceException on initialization exceptions
     */
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

    /**
     * Returns a verifier for the given public key and
     * algorithm using the default provider.
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
     * Returns a verifier for the given public key,
     * algorithm and provider.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static Verifier verifier(PublicKey publicKey, String algorithm, String provider) {
        return (message, signature) -> {
            try {
                final Signature signatureInstance = getSignature(algorithm, provider);
                signatureInstance.initVerify(publicKey);
                signatureInstance.update(message);
                return signatureInstance.verify(signature);
            } catch (InvalidKeyException e) {
                throw new BruceException(String.format("error verifying the signature: algorithm=%s, provider=%s", algorithm, provider), e);
            } catch (SignatureException e) {
                return false;
            }
        };
    }

    /**
     * Returns a verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key. This method uses the default provider.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm) {
        return verifier(publicKeyMap, algorithm, BLANK);
    }

    /**
     * Returns a verifier where the public key can be chosen at runtime.
     * The verification keys must be provided in a map where the map key is an
     * alias to the verification key and the value is the corresponding
     * verification key.
     *
     * @param publicKeyMap the verification key map
     * @param algorithm    the verification algorithm
     * @param provider     the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the verifier
     * @throws BruceException on no such algorithm or provider exceptions
     */
    public static VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm, String provider) {
        return (publicKeyId, message, signature) -> {
            PublicKey publicKey = publicKeyMap.get(publicKeyId);

            if (publicKey == null) {
                throw new BruceException(String.format("public key not found for id: %s", publicKeyId));
            }

            return verifier(publicKey, algorithm, provider).verify(message, signature);
        };
    }

    /**
     * Returns an encoding verifier for the given public key.
     * This method assumes the default messages charset is
     * {@link StandardCharsets#UTF_8}. The default provider
     * is used.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param encoding  the verification encoding
     * @return the verifier
     * @throws BruceException on initialization exceptions
     */
    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, Encoding encoding) {
        return verifier(publicKey, algorithm, BLANK, encoding);
    }

    /**
     * Returns an encoding verifier for the given public key.
     * This method assumes the default messages charset is
     * {@link StandardCharsets#UTF_8}.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the verification encoding
     * @return the verifier
     * @throws BruceException on initialization exceptions
     */
    public static EncodingVerifier verifier(PublicKey publicKey, String algorithm, String provider, Encoding encoding) {
        return verifier(publicKey, algorithm, provider, UTF_8, encoding);
    }

    /**
     * Returns an encoding verifier for the given public key.
     *
     * @param publicKey the verification key
     * @param algorithm the verification algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param charset   the charset used in messages
     * @param encoding  the verification encoding
     * @return the verifier
     * @throws BruceException on initialization exceptions
     */
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
     * Generates a symmetric key using the specified algorithm
     * and provider.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return a newly generated symmetric key
     */
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

    /**
     * Generates an encoded symmetric key using the specified algorithm.
     *
     * @param algorithm the key algorithm
     * @param encoding  the key encoding
     * @return a newly generated symmetric key
     */
    public static String symmetricKey(String algorithm, Encoding encoding) {
        return symmetricKey(algorithm, BLANK, encoding);
    }

    /**
     * Generates an encoded symmetric key using the specified algorithm
     * and provider.
     *
     * @param algorithm the key algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the key encoding
     * @return a newly generated symmetric key
     */
    public static String symmetricKey(String algorithm, String provider, Encoding encoding) {
        return encode(encoding, symmetricKey(algorithm, provider));
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return cipher(keyAlgorithm, cipherAlgorithm, BLANK, mode);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static CipherByKey cipher(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        return (key, iv, message) -> {
            try {
                final IvParameterSpec initializationVectorSpec = new IvParameterSpec(iv);
                final SecretKeySpec spec = new SecretKeySpec(key, keyAlgorithm);
                final javax.crypto.Cipher cipher = provider == null || provider.isBlank()
                        ? javax.crypto.Cipher.getInstance(cipherAlgorithm)
                        : javax.crypto.Cipher.getInstance(cipherAlgorithm, provider);
                switch (mode) {
                    case ENCRYPT:
                        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, spec, initializationVectorSpec);
                        break;
                    case DECRYPT:
                        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, spec, initializationVectorSpec);
                        break;
                }
                return cipher.doFinal(message);
            } catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IllegalBlockSizeException e) {
                throw new BruceException("error encrypting/decrypting message", e);
            }
        };
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the ciphering key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, Mode mode) {
        return cipher(key, keyAlgorithm, cipherAlgorithm, BLANK, mode);
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the ciphering key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @return the symmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.symmetric.Cipher cipher(byte[] key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode) {
        final CipherByKey cipher = cipher(keyAlgorithm, cipherAlgorithm, provider, mode);
        return (iv, message) -> cipher.encrypt(key, iv, message);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @return the symmetric cipher
     */
    public static EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset) {
        return cipherByKey(keyAlgorithm, cipherAlgorithm, BLANK, mode, charset);
    }

    /**
     * Returns a symmetric cipher where the key is selectable at runtime
     * through the returned interface.
     *
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @return the symmetric cipher
     */
    public static EncodingCipherByKey cipherByKey(String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset) {
        final CipherByKey cipher = cipher(keyAlgorithm, cipherAlgorithm, provider, mode);

        return (key, iv, message, encoding) -> {
            final byte[] keyBA = decode(encoding, key);
            final byte[] ivBA = decode(encoding, iv);

            switch (mode) {
                case ENCRYPT:
                    return encode(encoding, cipher.encrypt(keyBA, ivBA, message.getBytes(charset)));
                case DECRYPT:
                    return new String(cipher.encrypt(keyBA, ivBA, decode(encoding, message)), charset);
                default:
                    throw new BruceException("no such mode");
            }
        };
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the encryption/decryption key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @param encoding        the message encoding
     * @return the symmetric cipher
     */
    public static EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, Mode mode, Charset charset, Encoding encoding) {
        return cipher(key, keyAlgorithm, cipherAlgorithm, BLANK, mode, charset, encoding);
    }

    /**
     * Returns a symmetric cipher.
     *
     * @param key             the encryption/decryption key
     * @param keyAlgorithm    the key's algorithm
     * @param cipherAlgorithm the cipher's algorithm
     * @param provider        the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode            the encryption mode
     * @param charset         the message charset
     * @param encoding        the message encoding
     * @return the symmetric cipher
     */
    public static EncodingCipher cipher(String key, String keyAlgorithm, String cipherAlgorithm, String provider, Mode mode, Charset charset, Encoding encoding) {
        final EncodingCipherByKey cipher = cipherByKey(keyAlgorithm, cipherAlgorithm, provider, mode, charset);
        return (iv, message) -> cipher.encrypt(key, iv, message, encoding);
    }

    /**
     * Returns an asymmetric cipher.
     *
     * @param key       the ciphering key
     * @param algorithm the algorithm
     * @param mode      the encryption mode
     * @return the asymmetric cipher
     */
    public static Cipher cipher(Key key, String algorithm, Mode mode) {
        return cipher(key, algorithm, BLANK, mode);
    }

    /**
     * Returns an asymmetric cipher.
     *
     * @param key       the ciphering key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode      the encryption mode
     * @return the asymmetric cipher
     */
    public static Cipher cipher(Key key, String algorithm, String provider, Mode mode) {
        return message -> {
            try {
                final javax.crypto.Cipher cipher = provider == null || provider.isBlank()
                        ? javax.crypto.Cipher.getInstance(algorithm)
                        : javax.crypto.Cipher.getInstance(algorithm, provider);
                switch (mode) {
                    case ENCRYPT:
                        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
                        break;
                    case DECRYPT:
                        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
                        break;
                }
                return cipher.doFinal(message);
            } catch (Exception e) {
                throw new BruceException(String.format("error encrypting/decrypting message; mode=%s", mode), e);
            }
        };
    }

    /**
     * Returns an asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @return an asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm) {
        return cipher(keys, algorithm, BLANK);
    }

    /**
     * Returns an asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return an asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.CipherByKey cipher(Map<String, Key> keys, String algorithm, String provider) {
        // we use a cipher cache here as getting a new one each time is a bit expensive
        return (keyId, mode, message) -> getCipher(keys, keyId, algorithm, provider, mode).encrypt(message);
    }

    /**
     * Returns an encoding asymmetric cipher.
     *
     * @param key       the cipher's key
     * @param algorithm the algorithm
     * @param mode      the cipher mode: encrypt/decrypt
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, Mode mode, Encoding encoding, Charset charset) {
        return cipher(key, algorithm, BLANK, mode, encoding, charset);
    }

    /**
     * Returns an encoding asymmetric cipher.
     *
     * @param key       the cipher's key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param mode      the cipher mode: encrypt/decrypt
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipher cipher(Key key, String algorithm, String provider, Mode mode, Encoding encoding, Charset charset) {
        final Cipher cipher = cipher(key, algorithm, provider, mode);
        return message -> crypt(cipher, message, mode, encoding, charset);
    }

    /**
     * Returns an encoding asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, Encoding encoding, Charset charset) {
        return cipher(keys, algorithm, BLANK, encoding, charset);
    }

    /**
     * Returns an encoding asymmetric cipher with a map of preconfigured keys.
     *
     * @param keys      a map of keys where the key is the key id and the value is the key
     * @param algorithm the algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the message encoding
     * @param charset   the message charset
     * @return an encoding asymmetric cipher with a map of preconfigured keys
     */
    public static com.mirkocaserta.bruce.cipher.asymmetric.EncodingCipherByKey cipher(Map<String, Key> keys, String algorithm, String provider, Encoding encoding, Charset charset) {
        return (keyId, mode, message) -> {
            final Cipher cipher = getCipher(keys, keyId, algorithm, provider, mode);
            return crypt(cipher, message, mode, encoding, charset);
        };
    }

    /**
     * Performs encryption or decryption based on the given mode.
     *
     * @param cipher   the encryption/decryption cipher
     * @param message  the message
     * @param mode     the cipher mode: encrypt/decrypt
     * @param encoding the message encoding
     * @param charset  the message charset
     * @return the encrypted or decrypted message
     */
    private static String crypt(Cipher cipher, String message, Mode mode, Encoding encoding, Charset charset) {
        switch (mode) {
            case ENCRYPT:
                return encode(encoding, cipher.encrypt(message.getBytes(charset)));
            case DECRYPT:
                return new String(cipher.encrypt(decode(encoding, message)), charset);
            default:
                throw new BruceException("no such mode");
        }
    }

    /**
     * Returns a cipher using an internal cache.
     *
     * @param keys      a map of keys where keyId is the map key and the cipher key is the value
     * @param keyId     the key id
     * @param algorithm the cipher algorithm
     * @param provider  the provider
     * @param mode      the cipher mode: encrypt/decrypt
     * @return the cipher
     */
    private static Cipher getCipher(Map<String, Key> keys, String keyId, String algorithm, String provider, Mode mode) {
        return cipherCache.computeIfAbsent(cipherCacheKey(keyId, algorithm, provider, mode), ignored -> {
            final Key key = keys.get(keyId);
            if (key == null) {
                throw new BruceException(String.format("no such key: %s", keyId));
            }
            return cipher(key, algorithm, provider, mode);
        });
    }

    /**
     * This is used to generate the cipher cache key.
     *
     * @param keyId     the key id
     * @param algorithm the cypher algorithm
     * @param provider  the cypher provider
     * @param mode      the cyphering mode: encrypt/decrypt
     * @return the cache key
     */
    private static String cipherCacheKey(String keyId, String algorithm, String provider, Mode mode) {
        return keyId + "::" + algorithm + "::" + provider + "::" + mode;
    }

    /**
     * Returns an interface for producing message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @return the message authentication codes interface
     */
    public static Mac mac(Key key, String algorithm) {
        return mac(key, algorithm, BLANK);
    }

    /**
     * Returns an interface for producing message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @return the message authentication codes interface
     */
    public static Mac mac(Key key, String algorithm, String provider) {
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

    /**
     * Returns an interface for producing encoded message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @param encoding  the signature encoding
     * @param charset   the message charset
     * @return the message authentication codes interface
     */
    public static EncodingMac mac(Key key, String algorithm, Encoding encoding, Charset charset) {
        return mac(key, algorithm, BLANK, encoding, charset);
    }

    /**
     * Returns an interface for producing encoded message authentication codes.
     *
     * @param key       the secret key for digesting the messages
     * @param algorithm the signature algorithm
     * @param provider  the provider (hint: Bouncy Castle is <code>BC</code>)
     * @param encoding  the signature encoding
     * @param charset   the message charset
     * @return the message authentication codes interface
     */
    public static EncodingMac mac(Key key, String algorithm, String provider, Encoding encoding, Charset charset) {
        final Mac mac = mac(key, algorithm, provider);
        return message -> encode(encoding, mac.get(message.getBytes(charset)));
    }

    /**
     * Decodes the input using the specified encoding.
     *
     * @param encoding the encoding to use
     * @param input    the input to decode
     * @return a raw bytes array representation of the decoded input
     * @throws BruceException on decoding errors
     */
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
                    throw new BruceException("invalid encoding");
            }
        } catch (IllegalArgumentException e) {
            throw new BruceException(String.format("invalid input for encoding %s", encoding));
        }
    }

    /**
     * Encodes the input using the specified encoding.
     *
     * @param encoding the encoding to use
     * @param input    the input to encode
     * @return a string representation of the encoded input
     */
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
                throw new BruceException("invalid encoding");
        }
    }

    /**
     * Bruce supports these encodings. Encodings are used
     * in cryptography as a wire safe representation of raw
     * bytes which would otherwise get screwed-up in all
     * sort of possible ways while traversing networks or,
     * more generally, while exchanging hands.
     * <p>
     * Have you ever played the
     * <a href="https://en.wikipedia.org/wiki/Chinese_whispers">telephone game</a>?
     * Computers do that with raw bytes as different architectures
     * internally encode bytes in different ways. Unless you
     * use a standard encoding, messages get lost in translation
     * with catastrophic consequences.
     */
    public enum Encoding {
        /**
         * Hexadecimal encoding. For instance, the hexadecimal
         * encoding of a random MD5 hash is
         * <code>78e731027d8fd50ed642340b7c9a63b3</code>.
         */
        HEX,
        /**
         * Base64 encoding. For instance, the Base64 encoding of
         * a random MD5 hash is <code>eOcxAn2P1Q7WQjQLfJpjsw==</code>.
         */
        BASE64,
        /**
         * URL encoding. For instance, the URL encoding of a random
         * MD5 hash is <code>eOcxAn2P1Q7WQjQLfJpjsw==</code>.
         */
        URL,
        /**
         * MIME encoding. For instance, the MIME encoding of a random
         * MD5 hash is <code>eOcxAn2P1Q7WQjQLfJpjsw==</code>.
         */
        MIME
    }

}
