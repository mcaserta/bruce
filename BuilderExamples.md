# Builder Pattern Usage Examples

This document demonstrates the new builder patterns added to the Bruce cryptography library to reduce parameter overload and improve API ergonomics.

## Overview

The library now includes five builder classes:
- `CipherBuilder` - for complex cipher operations
- `SignerBuilder` - for complex signing operations  
- `VerifierBuilder` - for complex verification operations
- `DigestBuilder` - for complex digest operations
- `MacBuilder` - for complex MAC operations

## 1. VerifierBuilder Examples

### Basic Usage
```java
// Instead of: Bruce.verifier(publicKey, "SHA256withRSA", "BC", UTF_8, BASE64)
var verifier = Bruce.verifierBuilder()
    .key(publicKey)
    .algorithm("SHA256withRSA")
    .provider("BC")
    .charset(UTF_8)
    .encoding(BASE64)
    .build();

String signature = verifier.verify("Hello World", encodedSignature);
```

### Multi-Key Verifier
```java
Map<String, PublicKey> keys = Map.of("key1", publicKey1, "key2", publicKey2);

var verifier = Bruce.verifierBuilder()
    .keys(keys)
    .algorithm("SHA256withRSA")
    .encoding(HEX)
    .buildByKey();

boolean isValid = verifier.verify("key1", "Hello World", hexSignature);
```

### Raw Byte Verifier
```java
var rawVerifier = Bruce.verifierBuilder()
    .key(publicKey)
    .algorithm("SHA256withRSA")
    .buildRaw();

boolean isValid = rawVerifier.verify(messageBytes, signatureBytes);
```

## 2. DigestBuilder Examples

### Basic String Digester
```java
// Instead of: Bruce.digester("SHA-256", "BC", BASE64, UTF_8)
var digester = Bruce.digestBuilder()
    .algorithm("SHA-256")
    .provider("BC")
    .encoding(BASE64)
    .charset(UTF_8)
    .build();

String hash = digester.digest("Hello World");
```

### File Digester
```java
var fileDigester = Bruce.digestBuilder()
    .algorithm("SHA-512")
    .encoding(HEX)
    .buildFileDigester();

String fileHash = fileDigester.digest(new File("document.pdf"));
```

### Raw Byte Digester
```java
var rawDigester = Bruce.digestBuilder()
    .algorithm("MD5")
    .buildRaw();

byte[] hash = rawDigester.digest("Hello World".getBytes());
```

## 3. MacBuilder Examples

### Basic MAC Generation
```java
// Instead of: Bruce.mac(secretKey, "HmacSHA256", "BC", BASE64, UTF_8)
var mac = Bruce.macBuilder()
    .key(secretKey)
    .algorithm("HmacSHA256")
    .provider("BC")
    .encoding(BASE64)
    .charset(UTF_8)
    .build();

String authCode = mac.get("Hello World");
```

### Raw Byte MAC
```java
var rawMac = Bruce.macBuilder()
    .key(secretKey)
    .algorithm("HmacSHA1")
    .buildRaw();

byte[] authCode = rawMac.get("Hello World".getBytes());
```

## 4. CipherBuilder Examples (Enhanced Usage)

### Symmetric Cipher
```java
var cipher = Bruce.cipherBuilder()
    .key("myEncodedSecretKey")
    .algorithms("AES", "AES/CBC/PKCS5Padding")
    .mode(Mode.ENCRYPT)
    .provider("BC")
    .encoding(BASE64)
    .charset(UTF_8)
    .buildSymmetric();

String encrypted = cipher.encrypt("myIV", "Hello World");
```

### Asymmetric Cipher
```java
var cipher = Bruce.cipherBuilder()
    .key(rsaPublicKey)
    .algorithm("RSA/ECB/PKCS1Padding")
    .mode(Mode.ENCRYPT)
    .encoding(HEX)
    .buildAsymmetric();

String encrypted = cipher.encrypt("Hello World");
```

## 5. SignerBuilder Examples (Enhanced Usage)

### Multi-Key Signer
```java
Map<String, PrivateKey> signingKeys = loadSigningKeys();

var signer = Bruce.signerBuilder()
    .keys(signingKeys)
    .algorithm("SHA256withECDSA")
    .provider("BC")
    .encoding(BASE64)
    .buildByKey();

String signature = signer.sign("production-key", "Hello World");
```

## 6. Comparison: Before vs After

### Before (Complex Parameter Lists)
```java
// Hard to read, error-prone parameter ordering
var verifier = Bruce.verifier(publicKeyMap, "SHA256withRSA", "BC", UTF_8, BASE64);
var digester = Bruce.digester("SHA-512", "BC", HEX, UTF_8);
var mac = Bruce.mac(secretKey, "HmacSHA256", "BC", BASE64, UTF_8);
```

### After (Fluent Builders)
```java
// Clear, self-documenting, flexible parameter ordering
var verifier = Bruce.verifierBuilder()
    .keys(publicKeyMap)
    .algorithm("SHA256withRSA")
    .provider("BC")
    .charset(UTF_8)
    .encoding(BASE64)
    .buildByKey();

var digester = Bruce.digestBuilder()
    .algorithm("SHA-512")
    .provider("BC")
    .encoding(HEX)
    .charset(UTF_8)
    .build();

var mac = Bruce.macBuilder()
    .key(secretKey)
    .algorithm("HmacSHA256")
    .provider("BC")
    .encoding(BASE64)
    .charset(UTF_8)
    .build();
```

## 7. Configuration Reuse

Builders can be partially configured and reused:

```java
// Base configuration for all SHA-256 operations with Bouncy Castle
var baseDigestBuilder = Bruce.digestBuilder()
    .algorithm("SHA-256")
    .provider("BC")
    .charset(UTF_8);

// Specific configurations
var hexDigester = baseDigestBuilder.encoding(HEX).build();
var base64Digester = baseDigestBuilder.encoding(BASE64).build();
var fileDigester = baseDigestBuilder.encoding(HEX).buildFileDigester();
```

## Benefits

1. **Reduced Parameter Overload**: No more counting parameters or remembering their order
2. **Self-Documenting**: Method names clearly indicate what each parameter does
3. **Flexible Parameter Order**: Set parameters in any order that makes sense
4. **Default Values**: Sensible defaults for common use cases (UTF-8, BASE64, empty provider)
5. **Type Safety**: Compile-time validation of required parameters
6. **Extensibility**: Easy to add new parameters without breaking existing code
7. **Configuration Reuse**: Partial builders can be shared and extended

The builder pattern maintains backward compatibility while providing a more ergonomic API for complex cryptographic operations.