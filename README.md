# Bruce

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mcaserta_bruce&metric=alert_status)](https://sonarcloud.io/dashboard?id=mcaserta_bruce)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=mcaserta_bruce&metric=security_rating)](https://sonarcloud.io/dashboard?id=mcaserta_bruce)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=mcaserta_bruce&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=mcaserta_bruce)
[![Maven Central](https://img.shields.io/maven-central/v/com.mirkocaserta.bruce/bruce)](https://central.sonatype.com/artifact/com.mirkocaserta.bruce/bruce)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

**Bruce** is an ergonomic, lightweight, pure Java wrapper around the [Java Cryptography Architecture (JCA)](https://docs.oracle.com/en/java/docs/books/security/JCA-1.html). It makes common cryptographic operations straightforward without adding any runtime dependencies beyond the JDK.

## Features

- **Digital signatures** — sign and verify data with RSA, DSA, ECDSA, and more
- **Symmetric encryption** — AES-CBC, AES-GCM, DES, and other secret-key ciphers
- **Asymmetric encryption** — RSA public/private-key encryption and decryption
- **Message digests** — SHA-256, SHA-512, MD5, and any JCA-supported algorithm
- **Message Authentication Codes (MAC)** — HmacSHA256, HmacSHA512, and more
- **Keystore management** — load PKCS12/JKS keystores and serialize them to bytes, text, or files
- **Key generation** — generate RSA/DSA/EC key pairs and symmetric keys on the fly
- **PEM support** — read and write private keys, public keys, and certificates in PEM format
- **Multiple encodings** — HEX, BASE64, URL-safe BASE64, and MIME BASE64
- **Pluggable providers** — works with any JCA provider (e.g., [Bouncy Castle](https://www.bouncycastle.org/))
- **Multi-key APIs** — select a key by ID at call time for key-rotation scenarios
- **Type-safe algorithm enums** — compile-time safety and IDE auto-completion for all algorithm names
- **Zero runtime dependencies** — pure JDK, no extra JARs required at runtime

## Requirements

- Java 21 or later

## Installation

### Maven

```xml
<dependency>
    <groupId>com.mirkocaserta.bruce</groupId>
    <artifactId>bruce</artifactId>
    <version>2.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.mirkocaserta.bruce:bruce:2.0.0'
```

> Check [Maven Central](https://central.sonatype.com/artifact/com.mirkocaserta.bruce/bruce) for the latest release version.

## Quick Start

All operations are accessed through two static facades. Add these imports once at the top of your file:

```java
import static com.mirkocaserta.bruce.Bruce.*;
import static com.mirkocaserta.bruce.Bruce.Encoding.*;
import static com.mirkocaserta.bruce.Keystores.*;

// Optional: import algorithm enums for type-safe algorithm selection
import com.mirkocaserta.bruce.DigestAlgorithm;
import com.mirkocaserta.bruce.MacAlgorithm;
import com.mirkocaserta.bruce.SignatureAlgorithm;
import com.mirkocaserta.bruce.SymmetricAlgorithm;
import com.mirkocaserta.bruce.SymmetricCipherAlgorithm;
import com.mirkocaserta.bruce.AsymmetricAlgorithm;
```

## Usage Examples

### Loading Keys from a Keystore

```java
// Load a PKCS12 keystore from the classpath
KeyStore ks = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");

// Extract keys by alias
PrivateKey privateKey = privateKey(ks, "alice", "password".toCharArray());
PublicKey  publicKey  = publicKey(ks, "alice");
```

Keystores can be loaded from multiple sources:

| Prefix | Example |
|--------|---------|
| `classpath:` | `classpath:keystore.p12` |
| `file:` | `file:/etc/ssl/keystore.p12` |
| `http://` | `http://config-server/keystore.p12` |
| `https://` | `https://config-server/keystore.p12` |

### Keystore Serialization

```java
KeyStore ks = keystore("classpath:keystore.p12", "password", "PKCS12");

// Serialize to raw bytes
byte[] raw = keystoreToBytes(ks, "password");

// Serialize and encode for text transport
String base64 = keystoreToString(ks, "password", BASE64);

// Persist directly to disk
keystoreToFile(ks, "password", Path.of("/tmp/keystore-copy.p12"));
```

### Digital Signatures

```java
KeyStore ks         = keystore("classpath:keystore.p12", "password", "PKCS12");
PrivateKey signKey  = privateKey(ks, "alice", "password");
PublicKey  verifyKey = publicKey(ks, "alice");

// Create a signer and a verifier (string-based)
Signer   signer   = signerBuilder().key(signKey).algorithm("SHA256withRSA").build();
Verifier verifier = verifierBuilder().key(verifyKey).algorithm("SHA256withRSA").build();

// Or use the type-safe enum alternative:
Signer   signer2   = signerBuilder().key(signKey).algorithm(SignatureAlgorithm.SHA256_WITH_RSA).build();
Verifier verifier2 = verifierBuilder().key(verifyKey).algorithm(SignatureAlgorithm.SHA256_WITH_RSA).build();

// Sign
Bytes message   = Bytes.from("Hello, Bob!");
Bytes signature = signer.sign(message);

// Encode signature for transport
String b64Signature = signature.encode(BASE64);

// Verify (decode first, then verify)
Bytes sigFromB64 = Bytes.from(b64Signature, BASE64);
boolean valid    = verifier.verify(message, sigFromB64);
```

### Message Digest (Hashing)

```java
// String-based or enum-based algorithm selection
Digester sha256 = digestBuilder().algorithm("SHA-256").build();
Digester sha256e = digestBuilder().algorithm(DigestAlgorithm.SHA_256).build(); // equivalent
Digester sha512 = digestBuilder().algorithm("SHA-512").build();

Bytes hash    = sha256.digest(Bytes.from("Hello, World!"));
String hexHash = hash.encode(HEX);    // "dffd6021bb2bd5b0af676290809ec3a5..."
String b64Hash = hash.encode(BASE64); // "/fVgIbsr1v..."

// File hashing is streamed in chunks (does not load the full file in memory)
Bytes fileHashFromPath = sha256.digest(Path.of("/var/log/app.log"));
Bytes fileHashFromFile = sha256.digest(new File("/var/log/app.log"));
```

### Symmetric Encryption (AES)

```java
// Generate a random AES key
byte[] keyBytes = symmetricKey("AES");
byte[] ivBytes  = new byte[16];
new SecureRandom().nextBytes(ivBytes);

// Build encryptor and decryptor (string-based)
SymmetricEncryptor encryptor = cipherBuilder()
    .key(keyBytes)
    .algorithms("AES", "AES/CBC/PKCS5Padding")
    .buildSymmetricEncryptor();

SymmetricDecryptor decryptor = cipherBuilder()
    .key(keyBytes)
    .algorithms("AES", "AES/CBC/PKCS5Padding")
    .buildSymmetricDecryptor();

// Or use type-safe enums:
SymmetricEncryptor encryptor2 = cipherBuilder()
    .key(keyBytes)
    .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
    .buildSymmetricEncryptor();

Bytes iv         = Bytes.from(ivBytes);
Bytes cipherText = encryptor.encrypt(iv, Bytes.from("Secret message"));
Bytes plainText  = decryptor.decrypt(iv, cipherText);

// Encode for storage/transport
String encoded = cipherText.encode(BASE64);
```

### Asymmetric Encryption (RSA)

```java
// Generate an RSA key pair
KeyPair keyPair = keyPair("RSA", 2048);

AsymmetricEncryptor encryptor = cipherBuilder()
    .key(keyPair.getPublic())
    .algorithm("RSA/ECB/PKCS1Padding")
    .buildAsymmetricEncryptor();

AsymmetricDecryptor decryptor = cipherBuilder()
    .key(keyPair.getPrivate())
    .algorithm("RSA/ECB/PKCS1Padding")
    .buildAsymmetricDecryptor();

Bytes cipherText = encryptor.encrypt(Bytes.from("Top secret"));
Bytes plainText  = decryptor.decrypt(cipherText);
```

### Message Authentication Code (MAC)

```java
// Load a secret key from a keystore
KeyStore ks  = keystore("classpath:keystore.p12", "password");
Key secretKey = secretKey(ks, "hmac-key", "password");

Mac mac = macBuilder()
    .key(secretKey)
    .algorithm("HmacSHA256")
    .build();

Bytes data = Bytes.from("Authenticate me");
Bytes tag  = mac.sign(data);
String hexTag = tag.encode(HEX);
```

### PEM Support

```java
// Read keys from PEM strings
PrivateKey privKey = privateKeyFromPem("""
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
    -----END PRIVATE KEY-----
    """, "RSA");

PublicKey pubKey = publicKeyFromPem("""
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu7...
    -----END PUBLIC KEY-----
    """, "RSA");

// Convert keys back to PEM
String privatePem = keyToPem(privKey);
String publicPem  = keyToPem(pubKey);
```

### Key Generation

```java
// Generate key pairs
KeyPair rsaKeyPair = keyPair("RSA", 2048);
KeyPair ecKeyPair  = keyPair("EC", 256);
KeyPair dsaKeyPair = keyPair("DSA", 2048);

// Generate symmetric keys
byte[] aesKey    = symmetricKey("AES");
String b64AesKey = symmetricKey("AES", BASE64); // encoded for storage
```

### Multi-Key APIs

Bruce supports selecting a key by ID at runtime, which is useful for key-rotation scenarios:

```java
Map<String, PrivateKey> privateKeys = Map.of(
    "key-2023", privateKey(ks, "alice-2023", "password"),
    "key-2024", privateKey(ks, "alice-2024", "password")
);

SignerByKey signer = signerBuilder()
    .keys(privateKeys)
    .algorithm("SHA256withRSA")
    .buildByKey();

// Select the key to use at call time
Bytes signature = signer.sign("key-2024", Bytes.from("Hello"));
```

### Type-Safe Algorithm Enums

All builder methods that accept a raw algorithm string also accept a type-safe enum constant. This provides compile-time validation and IDE auto-completion as an alternative to remembering JCA algorithm name strings.

```java
// DigestAlgorithm
digestBuilder().algorithm(DigestAlgorithm.SHA_256).build();

// MacAlgorithm
macBuilder().key(key).algorithm(MacAlgorithm.HMAC_SHA_256).build();

// SignatureAlgorithm
signerBuilder().key(privateKey).algorithm(SignatureAlgorithm.SHA256_WITH_RSA).build();
verifierBuilder().key(publicKey).algorithm(SignatureAlgorithm.SHA256_WITH_RSA).build();

// SymmetricAlgorithm + SymmetricCipherAlgorithm
cipherBuilder()
    .key(keyBytes)
    .algorithms(SymmetricAlgorithm.AES, SymmetricCipherAlgorithm.AES_CBC_PKCS5)
    .buildSymmetricEncryptor();

// AsymmetricAlgorithm
cipherBuilder()
    .key(publicKey)
    .algorithm(AsymmetricAlgorithm.RSA_ECB_PKCS1)
    .buildAsymmetricEncryptor();
```

All enum types implement the `AlgorithmId` interface, which exposes the underlying JCA name via `algorithmName()`. The string-based overloads remain fully supported for custom or provider-specific algorithms not covered by the built-in enums.

### Using a Custom Provider

```java
// Use Bouncy Castle for extended algorithm support
Security.addProvider(new BouncyCastleProvider());

Digester digester = digestBuilder()
    .algorithm("BLAKE2b-256")
    .provider("BC")
    .build();
```

## The `Bytes` Type

`Bytes` is Bruce's universal currency type. It wraps a raw byte array and provides convenient conversions:

```java
// Construction
Bytes b1 = Bytes.from(new byte[]{1, 2, 3});       // raw bytes
Bytes b2 = Bytes.from("Hello");                    // UTF-8 text
Bytes b3 = Bytes.from("cafebabe", HEX);            // decode HEX
Bytes b4 = Bytes.from("c2lnbg==", BASE64);         // decode BASE64
Bytes b5 = Bytes.from(Path.of("secret.bin"));      // file contents
Bytes b6 = Bytes.fromPem("-----BEGIN ...");        // PEM-encoded DER

// Consumption
byte[] raw   = b2.asBytes();
String hex   = b2.encode(HEX);
String b64   = b2.encode(BASE64);
String text  = b2.asString();       // UTF-8
int    len   = b2.length();
boolean empty = b2.isEmpty();
```

## Building from Source

```bash
git clone https://github.com/mcaserta/bruce.git
cd bruce
./gradlew build
```

Run tests:

```bash
./gradlew test
```

Generate Javadoc:

```bash
./gradlew javadoc
```

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the issue and pull request workflow.

## License

Bruce is released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Links

- [Maven Central](https://central.sonatype.com/artifact/com.mirkocaserta.bruce/bruce)
- [Online documentation](https://bruce.mirkocaserta.com)
- [Issue tracker](https://github.com/mcaserta/bruce/issues)
