# Signatures

## Signer

Returns a `Signer` for the given private key and algorithm. All input and output
use the [`Bytes`](bytes.md) universal type — wrap your plaintext with
`Bytes.from(...)` and call `.encode(...)` or `.asString()` on the result.

### Usage examples

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
PrivateKey privateKey = privateKey(keystore, "alice", "password".toCharArray());

Signer signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA512withRSA")
    .build();

// raw bytes → raw bytes
Bytes rawSig = signer.sign(Bytes.from("Hello Bob".getBytes(UTF_8)));

// UTF-8 text → BASE64 signature string
Bytes sig    = signer.sign(Bytes.from("Hello Bob"));
String b64   = sig.encode(BASE64);

// UTF-8 text → HEX signature string
String hex   = signer.sign(Bytes.from("Hello Bob")).encode(HEX);

// ISO-8859-1 text → BASE64 signature string
Bytes sig2   = signer.sign(Bytes.from("Hello Bob", ISO_8859_1));
```

### Builder options

```java
import static com.mirkocaserta.bruce.Bruce.Provider.*;

Signer signer = signerBuilder()
    .key(privateKey)
    .algorithm("SHA512withRSA")
    .provider(BOUNCY_CASTLE)  // optional, defaults to JCA
    // .provider("BC")        // string-based alternative
    .build();
```

### Interface

```java
@FunctionalInterface
public interface Signer {
    Bytes sign(Bytes message);
}
```

Use [`Bytes`](bytes.md) factory methods to construct the message and `.encode()`
/ `.asString()` to consume the returned signature.

---

## Signer by Key

Returns a `SignerByKey` that resolves the private key at runtime from a
preconfigured map.

### Usage examples

```java
Map<String, PrivateKey> keys = Map.of("alice", aliceKey, "bob", bobKey);

SignerByKey signer = signerBuilder()
    .keys(keys)
    .algorithm("SHA512withRSA")
    .buildByKey();

// raw bytes → raw bytes
Bytes sig    = signer.sign("alice", Bytes.from("Hello Bob".getBytes(UTF_8)));

// UTF-8 text → BASE64 signature string
String b64   = signer.sign("alice", Bytes.from("Hello Bob")).encode(BASE64);

// UTF-8 text → HEX signature string
String hex   = signer.sign("bob", Bytes.from("Hello Alice")).encode(HEX);
```

### Interface

```java
@FunctionalInterface
public interface SignerByKey {
    Bytes sign(String privateKeyId, Bytes message);
}
```
