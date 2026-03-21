# Bytes

`com.mirkocaserta.bruce.Bytes` is the **universal currency type** for all Bruce
cryptographic operations. It is an immutable wrapper around a raw byte array
that can be constructed from — and converted to — a variety of representations
on demand.

Raw bytes are the canonical form; every other representation is simply a view.

## Construction

```java
// from a raw byte array
Bytes b = Bytes.from(new byte[]{0, 1, 2});

// from UTF-8 text
Bytes b = Bytes.from("Hello");

// from text with an explicit charset
Bytes b = Bytes.from("Hello", ISO_8859_1);

// by decoding a HEX-encoded string
Bytes b = Bytes.from("cafebabe", HEX);

// by decoding a BASE64-encoded string
Bytes b = Bytes.from("c2lnbg==", BASE64);

// from a file's full contents
Bytes b = Bytes.fromFile(Path.of("secret.bin"));
Bytes b = Bytes.fromFile(new File("secret.bin"));
```

## Consumption

```java
// get a defensive copy of the underlying byte array
byte[] raw    = b.asBytes();

// encode to a string representation
String base64 = b.encode(BASE64);
String hex    = b.encode(HEX);
String url    = b.encode(URL);
String mime   = b.encode(MIME);

// decode as UTF-8 string
String text   = b.asString();

// decode as string with explicit charset
String latin1 = b.asString(ISO_8859_1);

// utility
int     len   = b.length();
boolean empty = b.isEmpty();
```

## Equality

`Bytes` implements `equals` and `hashCode` based on the underlying byte array
content, so two `Bytes` instances wrapping identical bytes will be equal:

```java
Bytes a = Bytes.from("hello");
Bytes b = Bytes.from("hello");
assertEquals(a, b);  // true
```

## Why Bytes?

Previous Bruce versions provided dozens of overloaded methods — one for each
combination of input charset, output encoding, raw bytes, and text. `Bytes`
collapses all of that into a single type:

- **Builders** are simpler — no `.charset()` or `.encoding()` on builders.
- **Interfaces** are single-method functional interfaces — easy to lambda-ify.
- **You choose** how to interpret inputs and outputs at the call site, not at
  configuration time.
