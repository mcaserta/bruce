# Verification

## Verifier

Returns a `Verifier` for the given public key and algorithm. Both the message
and signature are passed as [`Bytes`](bytes.md); construct signatures from
encoded strings with `Bytes.from(encoded, encoding)`.

### Usage examples

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PublicKey publicKey = publicKey(keystore, "alice");

Verifier verifier = verifierBuilder()
    .key(publicKey)
    .algorithm("SHA512withRSA")
    .build();

// raw bytes + raw bytes → boolean
boolean ok = verifier.verify(
    Bytes.from("Hello Bob".getBytes(UTF_8)),
    rawSignature);

// UTF-8 text + BASE64 signature → boolean
boolean ok2 = verifier.verify(
    Bytes.from("Hello Bob"),
    Bytes.from(base64Signature, BASE64));

// UTF-8 text + HEX signature → boolean
boolean ok3 = verifier.verify(
    Bytes.from("Hello Bob"),
    Bytes.from(hexSignature, HEX));

// ISO-8859-1 text + BASE64 signature → boolean
boolean ok4 = verifier.verify(
    Bytes.from("Hello Bob", ISO_8859_1),
    Bytes.from(base64Signature, BASE64));
```

### Builder options

```java
Verifier verifier = verifierBuilder()
    .key(publicKey)
    .algorithm("SHA512withRSA")
    .provider("BC")          // optional, defaults to system provider
    .build();
```

### Interface

```java
@FunctionalInterface
public interface Verifier {
    boolean verify(Bytes message, Bytes signature);
}
```

---

## Verifier by Key

Returns a `VerifierByKey` that resolves the public key at runtime from a
preconfigured map.

### Usage examples

```java
Map<String, PublicKey> keys = Map.of("alice", alicePublicKey, "bob", bobPublicKey);

VerifierByKey verifier = verifierBuilder()
    .keys(keys)
    .algorithm("SHA512withRSA")
    .buildByKey();

// raw bytes + raw bytes → boolean
boolean ok = verifier.verify("alice",
    Bytes.from("Hello Bob".getBytes(UTF_8)), rawSignature);

// UTF-8 text + BASE64 signature → boolean
boolean ok2 = verifier.verify("alice",
    Bytes.from("Hello Bob"),
    Bytes.from(base64Signature, BASE64));

// UTF-8 text + HEX signature → boolean
boolean ok3 = verifier.verify("bob",
    Bytes.from("Hello Alice"),
    Bytes.from(hexSignature, HEX));
```

### Interface

```java
@FunctionalInterface
public interface VerifierByKey {
    boolean verify(String publicKeyId, Bytes message, Bytes signature);
}
```
