package com.mirkocaserta.bruce;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Main backward-compatible facade delegating to feature-focused facades.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bruce {
    /** Default binary-to-text encoding used by helper methods in the API. */
    public static final Encoding DEFAULT_ENCODING = Encoding.BASE64;
    /** Default charset used for text-to-bytes conversion in the API. */
    public static final Charset DEFAULT_CHARSET = UTF_8;

    private Bruce() {
        // utility class
    }

    /**
     * Creates a builder for symmetric and asymmetric cipher operations.
     *
     * @return a new {@link CipherBuilder}
     */
    public static CipherBuilder cipherBuilder() {
        return new CipherBuilder();
    }

    /**
     * Creates a builder for signer operations.
     *
     * @return a new {@link SignerBuilder}
     */
    public static SignerBuilder signerBuilder() {
        return new SignerBuilder();
    }

    /**
     * Creates a builder for verifier operations.
     *
     * @return a new {@link VerifierBuilder}
     */
    public static VerifierBuilder verifierBuilder() {
        return new VerifierBuilder();
    }

    /**
     * Creates a builder for digest operations.
     *
     * @return a new {@link DigestBuilder}
     */
    public static DigestBuilder digestBuilder() {
        return new DigestBuilder();
    }

    /**
     * Creates a builder for message authentication code operations.
     *
     * @return a new {@link MacBuilder}
     */
    public static MacBuilder macBuilder() {
        return new MacBuilder();
    }


    /** Supported binary-to-text encodings for serialized byte data. */
    public enum Encoding {
        /** Hexadecimal encoding. */
        HEX,
        /** Base64 encoding. */
        BASE64,
        /** URL-safe Base64 encoding. */
        URL,
        /** MIME Base64 encoding (line-broken). */
        MIME
    }
}
