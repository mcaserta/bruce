package com.mirkocaserta.bruce.impl.keystore;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.impl.util.Providers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Optional;

/**
 * Implementation class for keystore operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class KeyStoreOperations {
    
    private static final String BLANK = "";
    private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";
    
    private KeyStoreOperations() {
        // utility class
    }
    
    /**
     * Loads the default keystore using system properties.
     *
     * @return the default keystore
     */
    public static KeyStore loadDefaultKeyStore() {
        return loadKeyStore(DEFAULT_KEYSTORE_TYPE);
    }
    
    /**
     * Loads the default keystore with the specified type.
     *
     * @param type the keystore type
     * @return the loaded keystore
     */
    public static KeyStore loadKeyStore(String type) {
        return loadKeyStore(
                System.getProperty("javax.net.ssl.keyStore"),
                Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword")).orElse(BLANK).toCharArray(),
                type
        );
    }
    
    /**
     * Loads a keystore from a location using the default type.
     *
     * @param location the location (classpath:, http(s):, file:)
     * @param password the password
     * @return the loaded keystore
     */
    public static KeyStore loadKeyStore(String location, char[] password) {
        return loadKeyStore(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
    }
    
    /**
     * Loads a keystore from a location with a specific type.
     *
     * @param location the location (classpath:, http(s):, file:)
     * @param password the password
     * @param type the keystore type
     * @return the loaded keystore
     */
    public static KeyStore loadKeyStore(String location, char[] password, String type) {
        return loadKeyStore(location, password, type, BLANK);
    }
    
    /**
     * Loads a keystore from a location with a specific type and provider.
     *
     * @param location the location (classpath:, http(s):, file:)
     * @param password the password
     * @param type the keystore type
     * @param provider the JCA provider name
     * @return the loaded keystore
     */
    public static KeyStore loadKeyStore(String location, char[] password, String type, String provider) {
        if (location == null || location.isBlank()) {
            throw new BruceException("please provide a valid key store location");
        }

        try {
            Provider resolvedProvider = Providers.resolve(provider);
            var keyStore = resolvedProvider == null ?
                    KeyStore.getInstance(type) :
                    KeyStore.getInstance(type, resolvedProvider);
            try (InputStream inputStream = KeyStoreSources.open(location)) {
                keyStore.load(inputStream, password);
            }
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new BruceException(String.format("error loading keystore: location=%s", location), e);
        } catch (Exception e) {
            throw new BruceException("error loading keystore", e);
        }
    }
    
    /**
     * Loads a certificate by alias.
     *
     * @param keystore the keystore
     * @param alias the certificate alias
     * @return the certificate
     */
    public static Certificate loadCertificate(KeyStore keystore, String alias) {
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
     * Extracts a public key from a certificate stored under the alias.
     *
     * @param keystore the keystore
     * @param alias the certificate alias
     * @return the public key
     */
    public static PublicKey extractPublicKey(KeyStore keystore, String alias) {
        return loadCertificate(keystore, alias).getPublicKey();
    }
    
    /**
     * Loads a private key by alias.
     *
     * @param keystore the keystore
     * @param alias the private key alias
     * @param password the private key password
     * @return the private key
     */
    public static PrivateKey loadPrivateKey(KeyStore keystore, String alias, char[] password) {
        try {
            var privateKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(alias, new KeyStore.PasswordProtection(password));

            if (privateKeyEntry == null) {
                throw new BruceException(String.format("no such private key with alias: %s", alias));
            }

            return privateKeyEntry.getPrivateKey();
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            throw new BruceException(String.format("error loading private key with alias: %s", alias), e);
        }
    }
    
    /**
     * Loads a secret key by alias.
     *
     * @param keystore the keystore
     * @param alias the secret key alias
     * @param password the secret key password
     * @return the secret key
     */
    public static Key loadSecretKey(KeyStore keystore, String alias, char[] password) {
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
     * Serializes a keystore to raw bytes.
     *
     * @param keystore the keystore to serialize
     * @param password the keystore password
     * @return the serialized keystore bytes
     */
    public static byte[] storeKeyStore(KeyStore keystore, char[] password) {
        if (keystore == null) {
            throw new BruceException("keystore must not be null");
        }
        if (password == null) {
            throw new BruceException("password must not be null");
        }

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            keystore.store(outputStream, password);
            return outputStream.toByteArray();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new BruceException("error serializing keystore", e);
        }
    }

    /**
     * Serializes a keystore and writes it to disk.
     *
     * @param keystore the keystore to serialize
     * @param password the keystore password
     * @param path destination path
     */
    public static void storeKeyStore(KeyStore keystore, char[] password, Path path) {
        if (path == null) {
            throw new BruceException("path must not be null");
        }

        try {
            Files.write(path, storeKeyStore(keystore, password));
        } catch (IOException e) {
            throw new BruceException("error writing keystore to path: " + path, e);
        }
    }
}
