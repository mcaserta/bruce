package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.keystore.KeyGenerators;
import com.mirkocaserta.bruce.impl.keystore.KeyStoreOperations;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;
import com.mirkocaserta.bruce.impl.util.PemUtils;
import com.mirkocaserta.bruce.impl.util.Pkcs1Utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Feature-focused facade for keystore and key-management operations,
 * including keystore serialization to bytes, encoded strings, and files.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Keystores {

    /** Default keystore type used by Bruce when none is explicitly specified. */
    public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    private Keystores() {
        // utility class
    }

    /**
     * Loads an empty default-type keystore.
     *
     * @return loaded keystore instance
     */
    public static KeyStore keystore() {
        return KeyStoreOperations.loadDefaultKeyStore();
    }

    /**
     * Loads an empty keystore of the given type.
     *
     * @param type keystore type (for example {@code PKCS12} or {@code JKS})
     * @return loaded keystore instance
     */
    public static KeyStore keystore(String type) {
        return KeyStoreOperations.loadKeyStore(type);
    }

    /**
     * Loads a keystore from a location using the default keystore type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password) {
        return KeyStoreOperations.loadKeyStore(location, password);
    }

    /**
     * Loads a keystore from a location using the default keystore type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray());
    }

    /**
     * Loads a keystore from a location with explicit type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password, type);
    }

    /**
     * Loads a keystore from a location with explicit type.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password, String type) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type);
    }

    /**
     * Loads a keystore from a location with explicit type and provider.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @param provider provider name, or empty for default
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password, type, provider);
    }

    /**
     * Loads a keystore from a location with explicit type and provider.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @param provider provider selection
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, char[] password, String type, Bruce.Provider provider) {
        return KeyStoreOperations.loadKeyStore(location, password, type, providerName(provider));
    }

    /**
     * Loads a keystore from a location with explicit type and provider.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @param provider provider name, or empty for default
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password, String type, String provider) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type, provider);
    }

    /**
     * Loads a keystore from a location with explicit type and provider.
     *
     * @param location keystore location (classpath/file/http/https)
     * @param password keystore password
     * @param type keystore type
     * @param provider provider selection
     * @return loaded keystore
     */
    public static KeyStore keystore(String location, String password, String type, Bruce.Provider provider) {
        return KeyStoreOperations.loadKeyStore(location, password.toCharArray(), type, providerName(provider));
    }

    /**
     * Serializes a {@link KeyStore} to raw bytes.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @return serialized keystore bytes
     */
    public static byte[] keystoreToBytes(KeyStore keystore, char[] password) {
        return KeyStoreOperations.storeKeyStore(keystore, password);
    }

    /**
     * Serializes a {@link KeyStore} to raw bytes.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @return serialized keystore bytes
     */
    public static byte[] keystoreToBytes(KeyStore keystore, String password) {
        return KeyStoreOperations.storeKeyStore(keystore, password.toCharArray());
    }

    /**
     * Serializes a {@link KeyStore} and encodes the bytes as text.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @param encoding target text encoding
     * @return encoded serialized keystore
     */
    public static String keystoreToString(KeyStore keystore, char[] password, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, keystoreToBytes(keystore, password));
    }

    /**
     * Serializes a {@link KeyStore} and encodes the bytes as text.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @param encoding target text encoding
     * @return encoded serialized keystore
     */
    public static String keystoreToString(KeyStore keystore, String password, Bruce.Encoding encoding) {
        return EncodingUtils.encode(encoding, keystoreToBytes(keystore, password));
    }

    /**
     * Serializes a {@link KeyStore} to a file path.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @param path destination file path
     */
    public static void keystoreToFile(KeyStore keystore, char[] password, Path path) {
        KeyStoreOperations.storeKeyStore(keystore, password, path);
    }

    /**
     * Serializes a {@link KeyStore} to a file path.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @param path destination file path
     */
    public static void keystoreToFile(KeyStore keystore, String password, Path path) {
        KeyStoreOperations.storeKeyStore(keystore, password.toCharArray(), path);
    }

    /**
     * Serializes a {@link KeyStore} to a file.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @param file destination file
     */
    public static void keystoreToFile(KeyStore keystore, char[] password, File file) {
        KeyStoreOperations.storeKeyStore(keystore, password, file.toPath());
    }

    /**
     * Serializes a {@link KeyStore} to a file.
     *
     * @param keystore source keystore
     * @param password keystore password
     * @param file destination file
     */
    public static void keystoreToFile(KeyStore keystore, String password, File file) {
        KeyStoreOperations.storeKeyStore(keystore, password.toCharArray(), file.toPath());
    }

    /**
     * Loads a certificate by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias certificate alias
     * @return certificate instance
     */
    public static Certificate certificate(KeyStore keystore, String alias) {
        return KeyStoreOperations.loadCertificate(keystore, alias);
    }

    /**
     * Extracts a public key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @return public key
     */
    public static PublicKey publicKey(KeyStore keystore, String alias) {
        return KeyStoreOperations.extractPublicKey(keystore, alias);
    }

    /**
     * Loads a private key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password private key password
     * @return private key
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password.toCharArray());
    }

    /**
     * Loads a private key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password private key password
     * @return private key
     */
    public static PrivateKey privateKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadPrivateKey(keystore, alias, password);
    }

    /**
     * Loads a secret key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password secret key password
     * @return secret key
     */
    public static Key secretKey(KeyStore keystore, String alias, String password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password.toCharArray());
    }

    /**
     * Loads a secret key by alias from a keystore.
     *
     * @param keystore source keystore
     * @param alias key alias
     * @param password secret key password
     * @return secret key
     */
    public static Key secretKey(KeyStore keystore, String alias, char[] password) {
        return KeyStoreOperations.loadSecretKey(keystore, alias, password);
    }

    /**
     * Generates a key pair.
     *
     * @param algorithm key pair algorithm (for example {@code RSA} or {@code DSA})
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, keySize);
    }

    /**
     * Generates a key pair using an enum algorithm.
     *
     * @param algorithm key pair algorithm enum value
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(Bruce.AsymmetricKeyAlgorithm algorithm, int keySize) {
        return KeyGenerators.generateKeyPair(algorithmName(algorithm), keySize);
    }

    /**
     * Generates a key pair with explicit provider.
     *
     * @param algorithm key pair algorithm
     * @param provider provider name
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize);
    }

    /**
     * Generates a key pair with explicit provider using enum algorithm.
     *
     * @param algorithm key pair algorithm enum value
     * @param provider provider name
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(Bruce.AsymmetricKeyAlgorithm algorithm, String provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithmName(algorithm), provider, keySize);
    }

    /**
     * Generates a key pair with explicit provider.
     *
     * @param algorithm key pair algorithm
     * @param provider provider selection
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, Bruce.Provider provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithm, providerName(provider), keySize);
    }

    /**
     * Generates a key pair with explicit provider using enum algorithm.
     *
     * @param algorithm key pair algorithm enum value
     * @param provider provider selection
     * @param keySize key size in bits
     * @return generated key pair
     */
    public static KeyPair keyPair(Bruce.AsymmetricKeyAlgorithm algorithm, Bruce.Provider provider, int keySize) {
        return KeyGenerators.generateKeyPair(algorithmName(algorithm), providerName(provider), keySize);
    }

    /**
     * Generates a key pair using the given secure random source.
     *
     * @param algorithm key pair algorithm
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, keySize, random);
    }

    /**
     * Generates a key pair using enum algorithm and secure random source.
     *
     * @param algorithm key pair algorithm enum value
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(Bruce.AsymmetricKeyAlgorithm algorithm, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithmName(algorithm), keySize, random);
    }

    /**
     * Generates a key pair with explicit provider and secure random source.
     *
     * @param algorithm key pair algorithm
     * @param provider provider name
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, String provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, provider, keySize, random);
    }

    /**
     * Generates a key pair with explicit provider, enum algorithm, and secure random source.
     *
     * @param algorithm key pair algorithm enum value
     * @param provider provider name
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(Bruce.AsymmetricKeyAlgorithm algorithm, String provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithmName(algorithm), provider, keySize, random);
    }

    /**
     * Generates a key pair with explicit provider and secure random source.
     *
     * @param algorithm key pair algorithm
     * @param provider provider selection
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(String algorithm, Bruce.Provider provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithm, providerName(provider), keySize, random);
    }

    /**
     * Generates a key pair with enum algorithm, provider, and secure random source.
     *
     * @param algorithm key pair algorithm enum value
     * @param provider provider selection
     * @param keySize key size in bits
     * @param random secure random source
     * @return generated key pair
     */
    public static KeyPair keyPair(Bruce.AsymmetricKeyAlgorithm algorithm, Bruce.Provider provider, int keySize, SecureRandom random) {
        return KeyGenerators.generateKeyPair(algorithmName(algorithm), providerName(provider), keySize, random);
    }

    /**
     * Generates a random symmetric key.
     *
     * @param algorithm key algorithm (for example {@code AES})
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(String algorithm) {
        return KeyGenerators.generateSymmetricKey(algorithm);
    }

    /**
     * Generates a random symmetric key using enum algorithm.
     *
     * @param algorithm symmetric key algorithm enum value
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(Bruce.SymmetricKeyAlgorithm algorithm) {
        return KeyGenerators.generateSymmetricKey(algorithmName(algorithm));
    }

    /**
     * Generates a random symmetric key with explicit provider.
     *
     * @param algorithm key algorithm
     * @param provider provider name
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(String algorithm, String provider) {
        return KeyGenerators.generateSymmetricKey(algorithm, provider);
    }

    /**
     * Generates a random symmetric key with explicit provider using enum algorithm.
     *
     * @param algorithm symmetric key algorithm enum value
     * @param provider provider name
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(Bruce.SymmetricKeyAlgorithm algorithm, String provider) {
        return KeyGenerators.generateSymmetricKey(algorithmName(algorithm), provider);
    }

    /**
     * Generates a random symmetric key with explicit provider.
     *
     * @param algorithm key algorithm
     * @param provider provider selection
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(String algorithm, Bruce.Provider provider) {
        return KeyGenerators.generateSymmetricKey(algorithm, providerName(provider));
    }

    /**
     * Generates a random symmetric key with explicit provider using enum algorithm.
     *
     * @param algorithm symmetric key algorithm enum value
     * @param provider provider selection
     * @return raw symmetric key bytes
     */
    public static byte[] symmetricKey(Bruce.SymmetricKeyAlgorithm algorithm, Bruce.Provider provider) {
        return KeyGenerators.generateSymmetricKey(algorithmName(algorithm), providerName(provider));
    }

    /**
     * Generates a random symmetric key and encodes it.
     *
     * @param algorithm key algorithm
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(String algorithm, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, encoding);
    }

    /**
     * Generates a random symmetric key and encodes it using enum algorithm.
     *
     * @param algorithm symmetric key algorithm enum value
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(Bruce.SymmetricKeyAlgorithm algorithm, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithmName(algorithm), encoding);
    }

    /**
     * Generates a random symmetric key with explicit provider and encodes it.
     *
     * @param algorithm key algorithm
     * @param provider provider name
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(String algorithm, String provider, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, provider, encoding);
    }

    /**
     * Generates a random symmetric key with explicit provider and encodes it using enum algorithm.
     *
     * @param algorithm symmetric key algorithm enum value
     * @param provider provider name
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(Bruce.SymmetricKeyAlgorithm algorithm, String provider, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithmName(algorithm), provider, encoding);
    }

    /**
     * Generates a random symmetric key with explicit provider and encodes it.
     *
     * @param algorithm key algorithm
     * @param provider provider selection
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(String algorithm, Bruce.Provider provider, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithm, providerName(provider), encoding);
    }

    /**
     * Generates a random symmetric key with explicit provider and encodes it using enum algorithm.
     *
     * @param algorithm symmetric key algorithm enum value
     * @param provider provider selection
     * @param encoding output encoding
     * @return encoded key text
     */
    public static String symmetricKey(Bruce.SymmetricKeyAlgorithm algorithm, Bruce.Provider provider, Bruce.Encoding encoding) {
        return KeyGenerators.generateEncodedSymmetricKey(algorithmName(algorithm), providerName(provider), encoding);
    }

    private static String providerName(Bruce.Provider provider) {
        return provider == null ? "" : provider.providerName();
    }

    private static String algorithmName(Bruce.AsymmetricKeyAlgorithm algorithm) {
        return algorithm == null ? null : algorithm.algorithmName();
    }

    private static String algorithmName(Bruce.SymmetricKeyAlgorithm algorithm) {
        return algorithm == null ? null : algorithm.algorithmName();
    }

    // ── PEM helpers ──────────────────────────────────────────────────────────

    /**
     * Loads a {@link PrivateKey} from a PEM-encoded string (PKCS#8 format).
     *
     * @param pem       PEM string with {@code -----BEGIN PRIVATE KEY-----} header
     * @param algorithm key algorithm (e.g., {@code "RSA"}, {@code "EC"})
     * @return the private key
     * @throws BruceException if the PEM is invalid or the algorithm is unknown
     */
    public static PrivateKey privateKeyFromPem(String pem, String algorithm) {
        try {
            var spec = new PKCS8EncodedKeySpec(PemUtils.decode(pem));
            return KeyFactory.getInstance(algorithm).generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BruceException("error loading private key from PEM: algorithm=" + algorithm, e);
        }
    }

    /**
     * Loads a {@link PublicKey} from a PEM-encoded string (X.509/SubjectPublicKeyInfo format).
     *
     * @param pem       PEM string with {@code -----BEGIN PUBLIC KEY-----} header
     * @param algorithm key algorithm (e.g., {@code "RSA"}, {@code "EC"})
     * @return the public key
     * @throws BruceException if the PEM is invalid or the algorithm is unknown
     */
    public static PublicKey publicKeyFromPem(String pem, String algorithm) {
        try {
            var spec = new X509EncodedKeySpec(PemUtils.decode(pem));
            return KeyFactory.getInstance(algorithm).generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BruceException("error loading public key from PEM: algorithm=" + algorithm, e);
        }
    }

    /**
     * Loads an X.509 {@link Certificate} from a PEM-encoded string.
     *
     * @param pem PEM string with {@code -----BEGIN CERTIFICATE-----} header
     * @return the certificate
     * @throws BruceException if the PEM is invalid or the certificate cannot be parsed
     */
    public static Certificate certificateFromPem(String pem) {
        try {
            var factory = CertificateFactory.getInstance("X.509");
            var der = PemUtils.decode(pem);
            return factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new BruceException("error loading certificate from PEM", e);
        }
    }

    /**
     * Encodes a {@link Key} (public or private) as a PEM string.
     *
     * <p>Uses the key's own encoded form and applies the appropriate PEM label:
     * {@link PemType#PRIVATE_KEY} for private keys, {@link PemType#PUBLIC_KEY} for public keys,
     * and {@link PemType#SECRET_KEY} for secret (symmetric) keys.</p>
     *
     * @param key the key to encode
     * @return the PEM-encoded string
     * @throws BruceException if the key has no encoded form
     */
    public static String keyToPem(Key key) {
        var encoded = key.getEncoded();
        if (encoded == null) {
            throw new BruceException("key has no encoded form and cannot be PEM-encoded");
        }
        var type = switch (key) {
            case PrivateKey ignored -> PemType.PRIVATE_KEY;
            case PublicKey  ignored -> PemType.PUBLIC_KEY;
            default                 -> PemType.SECRET_KEY;
        };
        return PemUtils.encode(type, encoded);
    }

    /**
     * Encodes an X.509 {@link Certificate} as a PEM string.
     *
     * @param certificate the certificate to encode
     * @return the PEM-encoded string
     * @throws BruceException if the certificate cannot be encoded
     */
    public static String certificateToPem(Certificate certificate) {
        try {
            return PemUtils.encode(PemType.CERTIFICATE, certificate.getEncoded());
        } catch (CertificateException e) {
            throw new BruceException("error encoding certificate to PEM", e);
        }
    }

    // ── DER format ────────────────────────────────────────────────────────────

    /**
     * Loads a {@link PrivateKey} from raw DER bytes (PKCS#8 format).
     *
     * @param der       DER-encoded PKCS#8 private key bytes
     * @param algorithm key algorithm (e.g., {@code "RSA"}, {@code "EC"})
     * @return the private key
     * @throws BruceException if the bytes are invalid or the algorithm is unknown
     */
    public static PrivateKey privateKeyFromDer(byte[] der, String algorithm) {
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BruceException("error loading private key from DER: algorithm=" + algorithm, e);
        }
    }

    /**
     * Loads a {@link PublicKey} from raw DER bytes (X.509 SubjectPublicKeyInfo format).
     *
     * @param der       DER-encoded SubjectPublicKeyInfo public key bytes
     * @param algorithm key algorithm (e.g., {@code "RSA"}, {@code "EC"})
     * @return the public key
     * @throws BruceException if the bytes are invalid or the algorithm is unknown
     */
    public static PublicKey publicKeyFromDer(byte[] der, String algorithm) {
        try {
            return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new BruceException("error loading public key from DER: algorithm=" + algorithm, e);
        }
    }

    /**
     * Loads an X.509 {@link Certificate} from raw DER bytes.
     *
     * @param der DER-encoded X.509 certificate bytes
     * @return the certificate
     * @throws BruceException if the bytes cannot be parsed
     */
    public static Certificate certificateFromDer(byte[] der) {
        try {
            return CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new BruceException("error loading certificate from DER", e);
        }
    }

    /**
     * Exports a {@link Key} to raw DER bytes.
     *
     * <p>For private keys the output is PKCS#8 DER; for public keys it is
     * SubjectPublicKeyInfo (X.509) DER.</p>
     *
     * @param key the key to export
     * @return DER-encoded key bytes
     * @throws BruceException if the key has no encoded form
     */
    public static byte[] keyToDer(Key key) {
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new BruceException("key has no encoded form and cannot be DER-encoded");
        }
        return encoded;
    }

    /**
     * Exports an X.509 {@link Certificate} to raw DER bytes.
     *
     * @param certificate the certificate to export
     * @return DER-encoded certificate bytes
     * @throws BruceException if the certificate cannot be encoded
     */
    public static byte[] certificateToDer(Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new BruceException("error encoding certificate to DER", e);
        }
    }

    // ── PEM ↔ DER conversions ─────────────────────────────────────────────────

    /**
     * Converts a PEM-encoded string to raw DER bytes by stripping the headers
     * and Base64-decoding the body.
     *
     * <p>This is a format conversion only — no cryptographic parsing is done.</p>
     *
     * @param pem the PEM string; must not be {@code null} or blank
     * @return the raw DER bytes
     * @throws BruceException if the input is not valid PEM
     */
    public static byte[] pemToDer(String pem) {
        return PemUtils.decode(pem);
    }

    /**
     * Converts raw DER bytes to a PEM string with the given type label.
     *
     * <p>This is a format conversion only — no cryptographic parsing is done.</p>
     *
     * @param der  the raw DER bytes; must not be {@code null} or empty
     * @param type the PEM type (determines the BEGIN/END label)
     * @return the PEM-encoded string
     * @throws BruceException if either argument is invalid
     */
    public static String derToPem(byte[] der, PemType type) {
        return PemUtils.encode(type, der);
    }

    // ── PKCS#1 RSA format ─────────────────────────────────────────────────────

    /**
     * Loads an RSA {@link PrivateKey} from PKCS#1 DER bytes.
     *
     * <p>PKCS#1 is the traditional RSA-specific private key format, indicated by
     * {@code -----BEGIN RSA PRIVATE KEY-----} PEM headers.  Because the JDK only
     * understands PKCS#8, this method wraps the bytes in a PKCS#8 envelope
     * before parsing.</p>
     *
     * @param pkcs1Der PKCS#1 RSAPrivateKey DER bytes
     * @return the RSA private key
     * @throws BruceException if the bytes cannot be parsed
     */
    public static PrivateKey rsaPrivateKeyFromPkcs1(byte[] pkcs1Der) {
        return Pkcs1Utils.rsaPrivateKeyFromPkcs1(pkcs1Der);
    }

    /**
     * Loads an RSA {@link PrivateKey} from a PKCS#1 PEM string.
     *
     * <p>Accepts PEM with {@code -----BEGIN RSA PRIVATE KEY-----} headers.</p>
     *
     * @param pem PKCS#1 RSAPrivateKey PEM string
     * @return the RSA private key
     * @throws BruceException if the PEM is invalid
     */
    public static PrivateKey rsaPrivateKeyFromPkcs1Pem(String pem) {
        return Pkcs1Utils.rsaPrivateKeyFromPkcs1(PemUtils.decode(pem));
    }

    /**
     * Loads an RSA {@link PublicKey} from PKCS#1 DER bytes.
     *
     * <p>PKCS#1 is the traditional RSA-specific public key format, indicated by
     * {@code -----BEGIN RSA PUBLIC KEY-----} PEM headers.  Because the JDK only
     * understands SubjectPublicKeyInfo (X.509), this method wraps the bytes
     * in an SPKI envelope before parsing.</p>
     *
     * @param pkcs1Der PKCS#1 RSAPublicKey DER bytes
     * @return the RSA public key
     * @throws BruceException if the bytes cannot be parsed
     */
    public static PublicKey rsaPublicKeyFromPkcs1(byte[] pkcs1Der) {
        return Pkcs1Utils.rsaPublicKeyFromPkcs1(pkcs1Der);
    }

    /**
     * Loads an RSA {@link PublicKey} from a PKCS#1 PEM string.
     *
     * <p>Accepts PEM with {@code -----BEGIN RSA PUBLIC KEY-----} headers.</p>
     *
     * @param pem PKCS#1 RSAPublicKey PEM string
     * @return the RSA public key
     * @throws BruceException if the PEM is invalid
     */
    public static PublicKey rsaPublicKeyFromPkcs1Pem(String pem) {
        return Pkcs1Utils.rsaPublicKeyFromPkcs1(PemUtils.decode(pem));
    }

    /**
     * Exports an RSA private key to PKCS#1 DER bytes.
     *
     * <p>The JDK normally encodes RSA private keys in PKCS#8 format.  This
     * method extracts the inner RSAPrivateKey structure from the PKCS#8
     * envelope, yielding the traditional PKCS#1 DER bytes.</p>
     *
     * @param privateKey an RSA private key
     * @return PKCS#1 RSAPrivateKey DER bytes
     * @throws BruceException if the key cannot be encoded or is not RSA
     */
    public static byte[] rsaPrivateKeyToPkcs1(PrivateKey privateKey) {
        byte[] pkcs8 = privateKey.getEncoded();
        if (pkcs8 == null) {
            throw new BruceException("private key has no encoded form");
        }
        return Pkcs1Utils.pkcs8ToPkcs1PrivateKey(pkcs8);
    }

    /**
     * Exports an RSA private key as a PKCS#1 PEM string.
     *
     * <p>The returned string uses {@code -----BEGIN RSA PRIVATE KEY-----} headers.</p>
     *
     * @param privateKey an RSA private key
     * @return PKCS#1 RSAPrivateKey PEM string
     * @throws BruceException if the key cannot be encoded or is not RSA
     */
    public static String rsaPrivateKeyToPkcs1Pem(PrivateKey privateKey) {
        return PemUtils.encode(PemType.RSA_PRIVATE_KEY, rsaPrivateKeyToPkcs1(privateKey));
    }

    /**
     * Exports an RSA public key to PKCS#1 DER bytes.
     *
     * <p>The JDK normally encodes RSA public keys in SubjectPublicKeyInfo (X.509)
     * format.  This method extracts the inner RSAPublicKey structure, yielding the
     * traditional PKCS#1 DER bytes.</p>
     *
     * @param publicKey an RSA public key
     * @return PKCS#1 RSAPublicKey DER bytes
     * @throws BruceException if the key cannot be encoded or is not RSA
     */
    public static byte[] rsaPublicKeyToPkcs1(PublicKey publicKey) {
        byte[] spki = publicKey.getEncoded();
        if (spki == null) {
            throw new BruceException("public key has no encoded form");
        }
        return Pkcs1Utils.spkiToPkcs1PublicKey(spki);
    }

    /**
     * Exports an RSA public key as a PKCS#1 PEM string.
     *
     * <p>The returned string uses {@code -----BEGIN RSA PUBLIC KEY-----} headers.</p>
     *
     * @param publicKey an RSA public key
     * @return PKCS#1 RSAPublicKey PEM string
     * @throws BruceException if the key cannot be encoded or is not RSA
     */
    public static String rsaPublicKeyToPkcs1Pem(PublicKey publicKey) {
        return PemUtils.encode(PemType.RSA_PUBLIC_KEY, rsaPublicKeyToPkcs1(publicKey));
    }
}
