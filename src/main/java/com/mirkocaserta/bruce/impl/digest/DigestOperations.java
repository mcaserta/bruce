package com.mirkocaserta.bruce.impl.digest;

import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.EncodingDigester;
import com.mirkocaserta.bruce.digest.FileDigester;
import com.mirkocaserta.bruce.impl.util.EncodingUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Implementation class for digest operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class DigestOperations {
    
    private static final String BLANK = "";
    
    private DigestOperations() {
        // utility class
    }
    
    /**
     * Creates an encoding message digester using the default provider and UTF-8 charset.
     *
     * @param algorithm the digest algorithm
     * @param encoding the output encoding
     * @return an encoding digester
     */
    public static EncodingDigester createEncodingDigester(String algorithm, Bruce.Encoding encoding) {
        return createEncodingDigester(algorithm, BLANK, encoding, UTF_8);
    }
    
    /**
     * Creates an encoding message digester using the default provider and a custom charset.
     *
     * @param algorithm the digest algorithm
     * @param encoding the output encoding
     * @param charset the input charset
     * @return an encoding digester
     */
    public static EncodingDigester createEncodingDigester(String algorithm, Bruce.Encoding encoding, Charset charset) {
        return createEncodingDigester(algorithm, BLANK, encoding, charset);
    }
    
    /**
     * Creates an encoding message digester using a specific provider and UTF-8 charset.
     *
     * @param algorithm the digest algorithm
     * @param provider the JCA provider name
     * @param encoding the output encoding
     * @return an encoding digester
     */
    public static EncodingDigester createEncodingDigester(String algorithm, String provider, Bruce.Encoding encoding) {
        return createEncodingDigester(algorithm, provider, encoding, UTF_8);
    }
    
    /**
     * Creates an encoding message digester using a specific provider and charset.
     *
     * @param algorithm the digest algorithm
     * @param provider the JCA provider name
     * @param encoding the output encoding
     * @param charset the input charset
     * @return an encoding digester
     */
    public static EncodingDigester createEncodingDigester(String algorithm, String provider, Bruce.Encoding encoding, Charset charset) {
        if (encoding == null) {
            throw new BruceException("Invalid encoding: null");
        }

        var rawDigester = provider == null || provider.isBlank()
                ? createRawDigester(algorithm)
                : createRawDigester(algorithm, provider);

        return message -> EncodingUtils.encode(encoding, rawDigester.digest(message.getBytes(charset)));
    }
    
    /**
     * Creates a file digester using the default provider.
     *
     * @param algorithm the digest algorithm
     * @param encoding the output encoding
     * @return a file digester producing encoded hashes
     */
    public static FileDigester createFileDigester(String algorithm, Bruce.Encoding encoding) {
        return createFileDigester(algorithm, BLANK, encoding);
    }
    
    /**
     * Creates a file digester using a specific provider.
     *
     * @param algorithm the digest algorithm
     * @param provider the JCA provider name
     * @param encoding the output encoding
     * @return a file digester producing encoded hashes
     */
    public static FileDigester createFileDigester(String algorithm, String provider, Bruce.Encoding encoding) {
        if (encoding == null) {
            throw new BruceException("Invalid encoding: null");
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
                var digest = provider == null || provider.isBlank()
                        ? MessageDigest.getInstance(algorithm)
                        : MessageDigest.getInstance(algorithm, provider);
                try (var inputStream = new FileInputStream(file)) {
                    var buffer = new byte[8192];
                    int read;

                    while ((read = inputStream.read(buffer)) > 0) {
                        digest.update(buffer, 0, read);
                    }
                }
                return EncodingUtils.encode(encoding, digest.digest());
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
     * Creates a raw digester that returns bytes using an optional provider.
     *
     * @param algorithm the digest algorithm
     * @param provider the JCA provider name (blank for default)
     * @return a raw digester
     */
    public static Digester createRawDigester(String algorithm, String provider) {
        MessageDigest digester;

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
     * Creates a raw digester that returns bytes using the default provider.
     *
     * @param algorithm the digest algorithm
     * @return a raw digester
     */
    public static Digester createRawDigester(String algorithm) {
        return createRawDigester(algorithm, BLANK);
    }
}