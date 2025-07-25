# Signatures

## Signer

```java
Signer signer(PrivateKey privateKey, String algorithm);
```

 Returns a signer for the given private key and algorithm.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PrivateKey privateKey = privateKey(keystore, "alice", "password".toCharArray());
Signer signer = signer(privateKey, "SHA512withRSA");
byte[] signature = signer.sign("Hello".getBytes(UTF_8));
```

## Signer by Key

```text
SignerByKey signer(Map<String, PrivateKey> privateKeyMap, String algorithm)
```

 Returns a signer that allows choosing the private key at runtime from a map of preconfigured keys.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");

PrivateKey aKey = privateKey(keystore, "alice", "password".toCharArray());
PrivateKey bKey = privateKey(keystore, "bob", "password".toCharArray());

Map<String, PrivateKey> keys = Map.of("alice", aKey, "bob", bKey);

SignerByKey signer = signer(keys, "SHA512withRSA");

byte[] aSignature = signer.sign("alice", "Hello Bob".getBytes(UTF_8));
byte[] bSignature = signer.sign("bob", "Hello Alice".getBytes(UTF_8));
```

## Encoding Signer

```java
EncodingSigner signer(
    PrivateKey privateKey, 
    String algorithm, 
    Encoding encoding
);
```

 Returns an encoding signer for the given key, algorithm and encoding. Assumes using the default JCA provider and UTF-8 as the plaintext string character set encoding.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PrivateKey privateKey = privateKey(keystore, "alice", "password".toCharArray());
EncodingSigner signer = signer(privateKey, "SHA512withRSA", BASE64);
String signature = signer.sign("Hello");
```

##  Encoding Signer with Custom Character Set

```java
EncodingSigner signer(
    PrivateKey privateKey, 
    String algorithm, 
    Charset charset, 
    Encoding encoding
);
```

 Same as [encoding signer](sign.md#encoding-signer) but allows specifying a custom character set for the plaintext messages.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PrivateKey privateKey = privateKey(keystore, "alice", "password".toCharArray());
EncodingSigner signer = signer(privateKey, "SHA512withRSA", ISO_8859_1, BASE64);
String signature = signer.sign("Hello");
```

## Builder Pattern Alternative

For complex signer configurations, you can use the fluent builder API to avoid parameter overload:

### Basic Signer Builder

```java
EncodingSigner signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA512withRSA")
    .build();
String signature = signer.sign("Hello");
```

### Advanced Signer Builder

```java
EncodingSigner signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA512withRSA")
    .provider("BC")
    .charset(ISO_8859_1)
    .encoding(BASE64)
    .build();
String signature = signer.sign("Hello");
```

### Multi-Key Signer Builder

```java
Map<String, PrivateKey> keys = Map.of("alice", aKey, "bob", bKey);

EncodingSignerByKey signer = signerBuilder()
    .keys(keys)
    .algorithm("SHA512withRSA")
    .charset(UTF_8)
    .encoding(BASE64)
    .buildByKey();

String aSignature = signer.sign("alice", "Hello Bob");
String bSignature = signer.sign("bob", "Hello Alice");
```



