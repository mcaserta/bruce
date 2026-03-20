package com.mirkocaserta.bruce;

/**
 * Main backward-compatible facade delegating to feature-focused facades.
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public final class Bruce {
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
