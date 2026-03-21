package com.mirkocaserta.bruce;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Main backward-compatible facade delegating to feature-focused facades.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bruce {
    public static final Encoding DEFAULT_ENCODING = Encoding.BASE64;
    public static final Charset DEFAULT_CHARSET = UTF_8;

    private Bruce() {
        // utility class
    }

    public static CipherBuilder cipherBuilder() {
        return new CipherBuilder();
    }

    public static SignerBuilder signerBuilder() {
        return new SignerBuilder();
    }

    public static VerifierBuilder verifierBuilder() {
        return new VerifierBuilder();
    }

    public static DigestBuilder digestBuilder() {
        return new DigestBuilder();
    }

    public static MacBuilder macBuilder() {
        return new MacBuilder();
    }


    public enum Encoding {
        HEX,
        BASE64,
        URL,
        MIME
    }
}
