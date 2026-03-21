package com.mirkocaserta.bruce;

/**
 * Enumeration of standard PEM (Privacy-Enhanced Mail) type labels.
 *
 * <p>PEM is a text-based format for encoding cryptographic objects with Base64
 * content wrapped in BEGIN/END markers. Each type uses a label that identifies
 * the content type.</p>
 *
 * <p>Valid types are defined in:</p>
 * <ul>
 *   <li>RFC 7468 - "Encoding of Cryptographic Key, Certificate and CRL Objects"</li>
 *   <li>RFC 5958 - "Asymmetric Key Packages"</li>
 *   <li>RFC 5280 - "Internet X.509 Public Key Infrastructure Certificate and CRL Profile"</li>
 *   <li>RFC 5208 - "PKCS #8: Private-Key Information Syntax"</li>
 * </ul>
 *
 * @author Mirko Caserta (mirko.caserta@gmail.com)
 */
public enum PemType {

    /**
     * PKCS #8 format for private keys (RFC 5958).
     * Modern standard for encoding private keys of any algorithm.
     */
    PRIVATE_KEY("PRIVATE KEY"),

    /**
     * Traditional RSA private key format (PKCS #1).
     * Legacy format, often used for compatibility with older systems.
     */
    RSA_PRIVATE_KEY("RSA PRIVATE KEY"),

    /**
     * EC (Elliptic Curve) private key format (SEC1).
     * Traditional EC private key format.
     */
    EC_PRIVATE_KEY("EC PRIVATE KEY"),

    /**
     * X.509 SubjectPublicKeyInfo format for public keys (RFC 5280).
     * Standard format for encoding public keys of any algorithm.
     */
    PUBLIC_KEY("PUBLIC KEY"),

    /**
     * Traditional RSA public key format (PKCS #1).
     * Legacy format for RSA public keys.
     */
    RSA_PUBLIC_KEY("RSA PUBLIC KEY"),

    /**
     * EC (Elliptic Curve) public key format (SEC1).
     * Traditional EC public key format.
     */
    EC_PUBLIC_KEY("EC PUBLIC KEY"),

    /**
     * Encrypted PKCS #8 private key (RFC 5958).
     * Used for password-protected private keys.
     */
    ENCRYPTED_PRIVATE_KEY("ENCRYPTED PRIVATE KEY"),

    /**
     * X.509 certificate format (RFC 5280).
     * Standard format for X.509 public key certificates.
     */
    CERTIFICATE("CERTIFICATE"),

    /**
     * PKCS #10 certificate request format (RFC 2986).
     * Format for requesting a certificate from a Certificate Authority.
     */
    CERTIFICATE_REQUEST("CERTIFICATE REQUEST"),

    /**
     * X.509 Certificate Revocation List (RFC 5280).
     * Format for lists of revoked certificates.
     */
    CRL("CRL"),

    /**
     * X.509 Attribute Certificate (RFC 5755).
     * Attribute certificates are used to carry authorization and attribute information.
     */
    ATTRIBUTE_CERTIFICATE("ATTRIBUTE CERTIFICATE"),

    /**
     * OpenSSL/OpenSSH formatted encrypted private key.
     * Modern format used by OpenSSL and OpenSSH for encrypting private keys.
     */
    OPENSSH_PRIVATE_KEY("OPENSSH PRIVATE KEY"),

    /**
     * Generic secret (symmetric) key format.
     * Used for encoding symmetric keys that don't fit other standard formats.
     */
    SECRET_KEY("SECRET KEY");

    private final String label;

    PemType(String label) {
        this.label = label;
    }

    /**
     * Returns the PEM type label (the text between BEGIN/END markers).
     *
     * @return the PEM type label
     */
    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}

