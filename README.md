---
description: Java cryptography made easy
---

# Welcome

![](.gitbook/assets/logo%20%281%29.png)

Bruce is an ergonomic, lightweight, pure Java wrapper around the Java Cryptography API (version 2.0).

## Show Me the Code

Sure. Here are a few quick examples using static imports from `com.mirkocaserta.bruce.Bruce`.

### Digital Signatures

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password");
PrivateKey privateKey = privateKey(keystore, "alice", "password");

Signer signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA512withRSA")
    .encoding(BASE64)
    .build();

// bytes → bytes
byte[] rawSig = signer.sign("Hi Bob!".getBytes(UTF_8));

// String → BASE64 string (one-liner)
String sig = signer.signToString("Hi Bob!");
```

### Message Digest

```java
Digester digester = digestBuilder()
    .algorithm("SHA-256")
    .encoding(HEX)
    .build();

String hexHash = digester.digestToString("Hello World");
```

### Symmetric Encryption

```java
byte[] key = symmetricKey("AES");
byte[] iv  = new byte[16];
new SecureRandom().nextBytes(iv);

SymmetricEncryptor enc = symmetricEncryptorBuilder()
    .key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding")
    .encoding(BASE64).build();
SymmetricDecryptor dec = symmetricDecryptorBuilder()
    .key(key).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding")
    .encoding(BASE64).build();

String ivB64       = Base64.getEncoder().encodeToString(iv);
String cipherText  = enc.encryptToString(ivB64, "Hello World");
String plainText   = dec.decryptToString(ivB64, cipherText);
```

Bruce tries to reduce boilerplate to a minimum, so you can focus on your code.
