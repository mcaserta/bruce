---
description: Java cryptography made easy
---

# Welcome

![](.gitbook/assets/logo%20%281%29.png)

Bruce is an ergonomic, lightweight, pure Java wrapper around the Java
Cryptography API (version 2.0).

## Show Me the Code

Sure. Here are a few quick examples. Keystore and key helpers are static imports
from `com.mirkocaserta.bruce.Keystores`; builder factories are static imports
from `com.mirkocaserta.bruce.Bruce`.

### Digital Signatures

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PrivateKey privateKey = privateKey(keystore, "alice", "password".toCharArray());

Signer signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA512withRSA")
    .build();

// bytes → bytes (raw signature)
Bytes message   = Bytes.from("Hi Bob!");
Bytes rawSig    = signer.sign(message);

// raw bytes → BASE64 string
String b64Sig   = rawSig.encode(BASE64);

// BASE64 string → raw bytes (for verification)
Bytes sigFromB64 = Bytes.from(b64Sig, BASE64);
```

### Message Digest

```java
Digester digester = digestBuilder()
    .algorithm("SHA-256")
    .build();

Bytes hash   = digester.digest(Bytes.from("Hello World"));
String hex   = hash.encode(HEX);
String b64   = hash.encode(BASE64);
```

### Symmetric Encryption

```java
byte[] keyBytes = symmetricKey("AES");
byte[] ivBytes  = new byte[16];
new SecureRandom().nextBytes(ivBytes);

SymmetricEncryptor enc = cipherBuilder()
    .key(keyBytes).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding")
    .buildSymmetricEncryptor();
SymmetricDecryptor dec = cipherBuilder()
    .key(keyBytes).keyAlgorithm("AES").algorithm("AES/CBC/PKCS5Padding")
    .buildSymmetricDecryptor();

Bytes iv         = Bytes.from(ivBytes);
Bytes cipherText = enc.encrypt(iv, Bytes.from("Hello World"));
Bytes plainText  = dec.decrypt(iv, cipherText);

// convert to/from BASE64 for transport
String enc64  = cipherText.encode(BASE64);
Bytes fromB64 = Bytes.from(enc64, BASE64);
```

Bruce tries to reduce boilerplate to a minimum, so you can focus on your code.
