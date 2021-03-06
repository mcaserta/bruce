# Verification

## Verifier

```java
Verifier verifier(PublicKey publicKey, String algorithm);
```

 Returns a verifier for the given private key and algorithm.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PublicKey publicKey = publicKey(keystore, "alice");
Verifier verifier = verifier(publicKey, "SHA512withRSA");
byte[] signature = ...; 
boolean verified = verifier.verify("Hello".getBytes(UTF_8), signature);
```

## Verifier by Key

```text
VerifierByKey verifier(Map<String, PublicKey> publicKeyMap, String algorithm)
```

 Returns a verifier that allows choosing the public key at runtime from a map of preconfigured keys.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");

PublicKey aKey = publicKey(keystore, "alice");
PublicKey bKey = publicKey(keystore, "bob");

Map<String, PublicKey> keys = Map.of("alice", aKey, "bob", bKey);

VerifierByKey verifier = verifier(keys, "SHA512withRSA");

byte[] aSignature = ...; // Alice's signature
byte[] bSignature = ...; // Bob's signature

boolean verified = verifier.verify("alice", "Hello Alice".getBytes(UTF_8), bSignature);
boolean verified = verifier.verify("bob", "Hello Bob".getBytes(UTF_8), aSignature);
```

## Encoding Verifier

```java
EncodingVerifier verifier(
    PublicKey publicKey, 
    String algorithm, 
    Encoding encoding
);
```

 Returns an encoding verifier for the given key, algorithm and encoding. Assumes using the default JCA provider and UTF-8 as the plaintext string character set encoding.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PublicKey publicKey = publicKey(keystore, "alice");
EncodingVerifier verifier = verifier(publicKey, "SHA512withRSA", BASE64);
String signature = ...; // base64 encoded signature
boolean verified = verifier.verify("Hello", signature);
```

##  Encoding Verifier with Custom Character Set

```java
EncodingVerifier verifier(
    PublicKey publicKey, 
    String algorithm, 
    Charset charset, 
    Encoding encoding
);
```

 Same as [encoding verifier](verify.md#encoding-verifier) but allows specifying a custom character set for the plaintext messages.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PublicKey publicKey = publicKey(keystore, "alice");
EncodingVerifier verifier = verifier(publicKey, "SHA512withRSA", ISO_8859_1, BASE64);
String signature = ...; // base64 encoded signature
boolean verified = verifier.verify("Hello", signature);
```

