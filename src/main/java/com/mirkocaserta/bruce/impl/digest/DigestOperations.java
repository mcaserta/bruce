package com.mirkocaserta.bruce.impl.digest;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.impl.util.Providers;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Implementation class for digest operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class DigestOperations {

    private DigestOperations() {
        // utility class
    }

    public static Digester createDigester(String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);
        verifyAlgorithm(algorithm, resolvedProvider);

        return new Digester() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] digest(byte[] message) {
                try {
                    return newMessageDigest(algorithm, resolvedProvider).digest(message);
                } catch (NoSuchAlgorithmException e) {
                    throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
                }
            }

            @Override
            public byte[] digest(Path file) {
                try (var inputStream = Files.newInputStream(file)) {
                    var digest = newMessageDigest(algorithm, resolvedProvider);
                    var buffer = new byte[8192];
                    int read;

                    while ((read = inputStream.read(buffer)) > 0) {
                        digest.update(buffer, 0, read);
                    }

                    return digest.digest();
                } catch (NoSuchAlgorithmException e) {
                    throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
                } catch (IOException e) {
                    throw new BruceException(String.format("I/O error reading file: %s", file), e);
                }
            }
        };
    }

    private static void verifyAlgorithm(String algorithm, Provider provider) {
        try {
            newMessageDigest(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
        }
    }

    private static MessageDigest newMessageDigest(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        return provider == null
                ? MessageDigest.getInstance(algorithm)
                : MessageDigest.getInstance(algorithm, provider);
    }
}
