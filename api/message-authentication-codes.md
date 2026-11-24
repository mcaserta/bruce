# Message Authentication Codes

## Mac

Returns a `Mac` for the given key and algorithm. All input and output use the
[`Bytes`](bytes.md) universal type.

### Usage examples

```java
KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
Key key = secretKey(keystore, "hmac", "password".toCharArray());

Mac mac = macBuilder().key(key).algorithm("HmacSHA256").build();

// raw bytes → Bytes
Bytes rawMac = mac.get(Bytes.from("Hello there".getBytes(UTF_8)));

// UTF-8 text → BASE64 string
String b64 = mac.get(Bytes.from("Hello there")).encode(BASE64);

// UTF-8 text → HEX string
String hex = mac.get(Bytes.from("Hello there")).encode(HEX);

// explicit charset → BASE64 string
String b64_2 = mac.get(Bytes.from("Hello 👋🏻", UTF_16)).encode(BASE64);
```

### Verifying a MAC

Use `verify` to check a received tag. It recomputes the MAC and compares it in
constant time with `MessageDigest.isEqual`. Do not compare tags with
`Bytes.equals`, `Arrays.equals` or `String.equals` on the encoded form: those
return at the first differing byte and leak timing information that can help an
attacker forge a valid tag.

```java
// Alice sends the message and its tag
Mac alice = macBuilder().key(key).algorithm(MacAlgorithm.HMAC_SHA_256).build();
String tag = alice.get(Bytes.from("Hi Bob")).encode(BASE64);

// Bob, holding the same key, checks it
Mac bob = macBuilder().key(key).algorithm(MacAlgorithm.HMAC_SHA_256).build();
boolean authentic = bob.verify(Bytes.from("Hi Bob"), Bytes.from(tag, BASE64));
```

`verify` returns `false` for a wrong or tampered tag, including one of a
different length, and throws `BruceException` if `message` or `tag` is `null`.

### Builder options

```java
import static com.mirkocaserta.bruce.Bruce.Provider.*;

// String-based algorithm (open-ended, supports any JCA algorithm)
Mac mac = macBuilder()
    .key(secretKey)
    .algorithm("HmacSHA256")
    .provider(BOUNCY_CASTLE)  // optional, defaults to JCA
    // .provider("BC")        // string-based alternative
    .build();

// Enum-based algorithm (type-safe, IDE auto-completion)
Mac mac2 = macBuilder()
    .key(secretKey)
    .algorithm(MacAlgorithm.HMAC_SHA_256)
    .provider(BOUNCY_CASTLE)  // optional
    .build();
```

Available `MacAlgorithm` constants: `HMAC_MD5`, `HMAC_SHA_1`, `HMAC_SHA_224`,
`HMAC_SHA_256`, `HMAC_SHA_384`, `HMAC_SHA_512`, `HMAC_SHA_512_224`,
`HMAC_SHA_512_256`, `HMAC_SHA3_224`, `HMAC_SHA3_256`, `HMAC_SHA3_384`,
`HMAC_SHA3_512`.

`HMAC_MD5` and `HMAC_SHA_1` are weak: kept for interoperability only; prefer
`HMAC_SHA_256`.

### Interface

```java
@FunctionalInterface
public interface Mac {
    Bytes get(Bytes message);

    // constant-time comparison of get(message) against tag
    default boolean verify(Bytes message, Bytes tag) { ... }
}
```

### Input / output combinations

| Input          | How to construct                      | Consume output                     |
| -------------- | ------------------------------------- | ---------------------------------- |
| raw `byte[]`   | `Bytes.from(rawBytes)`                | `.asBytes()`                       |
| UTF-8 text     | `Bytes.from("text")`                  | `.encode(HEX)` / `.encode(BASE64)` |
| custom charset | `Bytes.from("text", charset)`         | `.encode(...)`                     |
| encoded string | `Bytes.from("abc…", Encoding.BASE64)` | `.encode(...)`                     |
