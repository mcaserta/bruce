package com.mirkocaserta.bruce.impl.mac;

import com.mirkocaserta.bruce.Bytes;
import com.mirkocaserta.bruce.BruceException;
import com.mirkocaserta.bruce.impl.util.Providers;
import com.mirkocaserta.bruce.mac.Mac;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Implementation class for MAC (Message Authentication Code) operations.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class MacOperations {

    private MacOperations() {}

    public static Mac createMac(Key key, String algorithm, String provider) {
        Provider resolvedProvider = Providers.resolve(provider);
        return message -> {
            try {
                var mac = resolvedProvider == null
                        ? javax.crypto.Mac.getInstance(algorithm)
                        : javax.crypto.Mac.getInstance(algorithm, resolvedProvider);
                mac.init(key);
                return Bytes.from(mac.doFinal(message.asBytes()));
            } catch (NoSuchAlgorithmException e) {
                throw new BruceException(String.format("no such algorithm: %s", algorithm), e);
            } catch (InvalidKeyException e) {
                throw new BruceException("invalid key", e);
            }
        };
    }
}
