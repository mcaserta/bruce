package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.impl.mac.MacOperations;
import com.mirkocaserta.bruce.mac.EncodingMac;
import com.mirkocaserta.bruce.mac.Mac;

import java.nio.charset.Charset;
import java.security.Key;

/**
 * Feature-focused facade for message authentication code operations.
 */
public final class Macs {

    private Macs() {
        // utility class
    }

    public static Mac mac(Key key, String algorithm) {
        return MacOperations.createMac(key, algorithm);
    }

    public static Mac mac(Key key, String algorithm, String provider) {
        return MacOperations.createMac(key, algorithm, provider);
    }

    public static EncodingMac mac(Key key, String algorithm, Bruce.Encoding encoding, Charset charset) {
        return MacOperations.createEncodingMac(key, algorithm, encoding, charset);
    }

    public static EncodingMac mac(Key key, String algorithm, String provider, Bruce.Encoding encoding, Charset charset) {
        return MacOperations.createEncodingMac(key, algorithm, provider, encoding, charset);
    }
}
