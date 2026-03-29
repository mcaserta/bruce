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

    /** Supported JCA provider selections for provider-aware operations. */
    public enum Provider {
        /** Use the JVM default provider chain. */
        JCA(""),
        /** Use the Bouncy Castle provider. */
        BOUNCY_CASTLE("BC"),
        /** Use the Conscrypt provider. */
        CONSCRYPT("Conscrypt");

        private final String providerName;

        Provider(String providerName) {
            this.providerName = providerName;
        }

        /**
         * Returns the configured provider name.
         *
         * @return the JCA provider name understood by {@code Security.getProvider}
         */
        public String providerName() {
            return providerName;
        }
    }

    /** Curated digest algorithms exposed as enum alternatives to raw strings. */
    public enum DigestAlgorithm {
        /** SHA-1 digest algorithm. */
        SHA_1("SHA-1"),
        /** SHA-224 digest algorithm. */
        SHA_224("SHA-224"),
        /** SHA-256 digest algorithm. */
        SHA_256("SHA-256"),
        /** SHA-384 digest algorithm. */
        SHA_384("SHA-384"),
        /** SHA-512 digest algorithm. */
        SHA_512("SHA-512"),
        /** MD5 digest algorithm. */
        MD5("MD5");

        private final String algorithmName;

        DigestAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        /**
         * Returns the JCA algorithm name.
         *
         * @return the digest algorithm name
         */
        public String algorithmName() {
            return algorithmName;
        }
    }

    /** Curated MAC algorithms exposed as enum alternatives to raw strings. */
    public enum MacAlgorithm {
        /** HmacMD5 MAC algorithm. */
        HMAC_MD5("HmacMD5"),
        /** HmacSHA1 MAC algorithm. */
        HMAC_SHA1("HmacSHA1"),
        /** HmacSHA256 MAC algorithm. */
        HMAC_SHA256("HmacSHA256"),
        /** HmacSHA384 MAC algorithm. */
        HMAC_SHA384("HmacSHA384"),
        /** HmacSHA512 MAC algorithm. */
        HMAC_SHA512("HmacSHA512");

        private final String algorithmName;

        MacAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        /**
         * Returns the JCA algorithm name.
         *
         * @return the MAC algorithm name
         */
        public String algorithmName() {
            return algorithmName;
        }
    }

    /** Curated signature algorithms exposed as enum alternatives to raw strings. */
    public enum SignatureAlgorithm {
        /** SHA1withRSA signature algorithm. */
        SHA1_WITH_RSA("SHA1withRSA"),
        /** SHA256withRSA signature algorithm. */
        SHA256_WITH_RSA("SHA256withRSA"),
        /** SHA384withRSA signature algorithm. */
        SHA384_WITH_RSA("SHA384withRSA"),
        /** SHA512withRSA signature algorithm. */
        SHA512_WITH_RSA("SHA512withRSA"),
        /** SHA256withECDSA signature algorithm. */
        SHA256_WITH_ECDSA("SHA256withECDSA"),
        /** SHA384withECDSA signature algorithm. */
        SHA384_WITH_ECDSA("SHA384withECDSA"),
        /** SHA512withECDSA signature algorithm. */
        SHA512_WITH_ECDSA("SHA512withECDSA");

        private final String algorithmName;

        SignatureAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        /**
         * Returns the JCA algorithm name.
         *
         * @return the signature algorithm name
         */
        public String algorithmName() {
            return algorithmName;
        }
    }

    /** Curated asymmetric key algorithms exposed as enum alternatives to raw strings. */
    public enum AsymmetricKeyAlgorithm {
        /** RSA key-pair algorithm. */
        RSA("RSA"),
        /** DSA key-pair algorithm. */
        DSA("DSA"),
        /** Elliptic Curve key-pair algorithm. */
        EC("EC");

        private final String algorithmName;

        AsymmetricKeyAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        /**
         * Returns the JCA algorithm name.
         *
         * @return the asymmetric key algorithm name
         */
        public String algorithmName() {
            return algorithmName;
        }
    }

    /** Curated symmetric key algorithms exposed as enum alternatives to raw strings. */
    public enum SymmetricKeyAlgorithm {
        /** AES symmetric key algorithm. */
        AES("AES"),
        /** DES symmetric key algorithm. */
        DES("DES"),
        /** Triple DES symmetric key algorithm. */
        DESEDE("DESede"),
        /** HmacSHA1 key algorithm. */
        HMAC_SHA1("HmacSHA1"),
        /** HmacSHA256 key algorithm. */
        HMAC_SHA256("HmacSHA256"),
        /** HmacSHA384 key algorithm. */
        HMAC_SHA384("HmacSHA384"),
        /** HmacSHA512 key algorithm. */
        HMAC_SHA512("HmacSHA512");

        private final String algorithmName;

        SymmetricKeyAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        /**
         * Returns the JCA algorithm name.
         *
         * @return the symmetric key algorithm name
         */
        public String algorithmName() {
            return algorithmName;
        }
    }

    /** Curated cipher transformations exposed as enum alternatives to raw strings. */
    public enum CipherAlgorithm {
        /** RSA transformation using provider defaults. */
        RSA("RSA"),
        /** RSA/ECB/PKCS1Padding transformation. */
        RSA_ECB_PKCS1PADDING("RSA/ECB/PKCS1Padding"),
        /** AES/CBC/PKCS5Padding transformation. */
        AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding"),
        /** DESede/CBC/PKCS5Padding transformation. */
        DESEDE_CBC_PKCS5PADDING("DESede/CBC/PKCS5Padding");

        private final String algorithmName;

        CipherAlgorithm(String algorithmName) {
            this.algorithmName = algorithmName;
        }

        /**
         * Returns the JCA transformation name.
         *
         * @return the cipher algorithm name
         */
        public String algorithmName() {
            return algorithmName;
        }
    }
}
