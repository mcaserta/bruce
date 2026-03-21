package com.mirkocaserta.bruce.impl.digest;

import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.impl.util.Providers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Implementation class for digest operations.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class DigestOperations {

    private DigestOperations() {}

    public static Digester createDigester(String algorithm, String provider) {
        Provider resolvedProvider = Providers.resolve(provider);
        verifyAlgorithm(algorithm, resolvedProvider);

        return new Digester() {
            @Override
            public Bytes digest(Bytes input) {
                try {
                    return Bytes.from(newMessageDigest(algorithm, resolvedProvider).digest(input.asBytes()));
                } catch (NoSuchAlgorithmException e) {
                    throw new BruceException(String.format("No such algorithm: %s", algorithm), e);
                }
            }

            @Override
            public Bytes digest(Path file) {
                try (var inputStream = Files.newInputStream(file)) {
                    var digest = newMessageDigest(algorithm, resolvedProvider);
                    var buffer = new byte[8192];
                    int read;
                    while ((read = inputStream.read(buffer)) > 0) {
                        digest.update(buffer, 0, read);
                    }
                    return Bytes.from(digest.digest());
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
