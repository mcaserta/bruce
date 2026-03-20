package com.mirkocaserta.bruce;

import com.mirkocaserta.bruce.digest.Digester;
import com.mirkocaserta.bruce.digest.EncodingDigester;
import com.mirkocaserta.bruce.digest.FileDigester;
import com.mirkocaserta.bruce.impl.digest.DigestOperations;

import java.nio.charset.Charset;

/**
 * Feature-focused facade for digest operations.
 */
public final class Digests {

    private Digests() {
        // utility class
    }

    public static EncodingDigester digester(String algorithm, Bruce.Encoding encoding) {
        return DigestOperations.createEncodingDigester(algorithm, encoding);
    }

    public static EncodingDigester digester(String algorithm, Bruce.Encoding encoding, Charset charset) {
        return DigestOperations.createEncodingDigester(algorithm, encoding, charset);
    }

    public static EncodingDigester digester(String algorithm, String provider, Bruce.Encoding encoding) {
        return DigestOperations.createEncodingDigester(algorithm, provider, encoding);
    }

    public static EncodingDigester digester(String algorithm, String provider, Bruce.Encoding encoding, Charset charset) {
        return DigestOperations.createEncodingDigester(algorithm, provider, encoding, charset);
    }

    public static FileDigester fileDigester(String algorithm, Bruce.Encoding encoding) {
        return DigestOperations.createFileDigester(algorithm, encoding);
    }

    public static FileDigester fileDigester(String algorithm, String provider, Bruce.Encoding encoding) {
        return DigestOperations.createFileDigester(algorithm, provider, encoding);
    }

    public static Digester digester(String algorithm, String provider) {
        return DigestOperations.createRawDigester(algorithm, provider);
    }

    public static Digester digester(String algorithm) {
        return DigestOperations.createRawDigester(algorithm);
    }
}
