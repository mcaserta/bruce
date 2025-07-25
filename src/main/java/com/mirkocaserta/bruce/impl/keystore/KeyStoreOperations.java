package com.mirkocaserta.bruce.impl.keystore;

import com.mirkocaserta.bruce.BruceException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
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
    
    public static KeyStore loadDefaultKeyStore() {
        return loadKeyStore(DEFAULT_KEYSTORE_TYPE);
    }
    
    public static KeyStore loadKeyStore(String type) {
        return loadKeyStore(
                System.getProperty("javax.net.ssl.keyStore"),
                Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword")).orElse(BLANK).toCharArray(),
                type
        );
    }
    
    public static KeyStore loadKeyStore(String location, char[] password) {
        return loadKeyStore(location, password, DEFAULT_KEYSTORE_TYPE, BLANK);
    }
    
    public static KeyStore loadKeyStore(String location, char[] password, String type) {
        return loadKeyStore(location, password, type, BLANK);
    }
    
    public static KeyStore loadKeyStore(String location, char[] password, String type, String provider) {
        if (location == null || location.isBlank()) {
            throw new BruceException("please provide a valid key store location");
        }

        try {
            var keyStore = provider == null || provider.isBlank() ?
                    KeyStore.getInstance(type) :
                    KeyStore.getInstance(type, provider);
            InputStream inputStream;
            if (location.startsWith("classpath:")) {
                inputStream = KeyStoreOperations.class.getResourceAsStream(location.replaceFirst("classpath:", BLANK));
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
            throw new BruceException(String.format("error loading keystore, no such provider: provider=%s", provider), e);
        } catch (Exception e) {
            throw new BruceException("error loading keystore", e);
        }
    }
    
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
    
    public static PublicKey extractPublicKey(KeyStore keystore, String alias) {
        return loadCertificate(keystore, alias).getPublicKey();
    }
    
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
}