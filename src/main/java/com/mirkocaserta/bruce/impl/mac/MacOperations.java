package com.mirkocaserta.bruce.impl.mac;

import com.mirkocaserta.bruce.Bruce;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.impl.util.Providers;
import com.mirkocaserta.bruce.mac.Mac;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Implementation class for MAC (Message Authentication Code) operations.
 * This class is package-private and should only be accessed through the Bruce facade.
 * 
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class MacOperations {

    private MacOperations() {
        // utility class
    }

    public static Mac createMac(Key key, String algorithm, String provider, Charset charset, Bruce.Encoding encoding) {
        Provider resolvedProvider = Providers.resolve(provider);

        return new Mac() {
            @Override
            public Charset charset() {
                return charset;
            }

            @Override
            public Bruce.Encoding encoding() {
                return encoding;
            }

            @Override
            public byte[] get(byte[] message) {
                try {
                    var mac = resolvedProvider == null
                            ? javax.crypto.Mac.getInstance(algorithm)
                            : javax.crypto.Mac.getInstance(algorithm, resolvedProvider);
                    mac.init(key);
                    return mac.doFinal(message);
                } catch (NoSuchAlgorithmException e) {
                    throw new BruceException(String.format("no such algorithm: %s", algorithm), e);
                } catch (InvalidKeyException e) {
                    throw new BruceException("invalid key", e);
                }
            }
        };
    }
}
