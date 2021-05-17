---
description: Java cryptography made easy
---

# Welcome

![](.gitbook/assets/logo.png)

Bruce is an ergonomic, lightweight, pure Java wrapper around the Java Cryptography API.

## Show Me the Code

Sure. Here's an example for base64 encoded digital signatures.

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password");
PrivateKey privateKey = privateKey(keystore, "alice", "password");
EncodingSigner signer = signer(privateKey, "SHA512withRSA", BASE64);
String signature = signer.sign("Hi Bob!");
```



