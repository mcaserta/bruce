# Digests

## Digester

```java
Digester digester(String algorithm);
```

 Returns a raw bytes digester for the given algorithm.

### Usage Example

```java
Digester digester = digester("SHA1");
byte[] hash = digester.digest("hello".getBytes(StandardCharsets.UTF_8));
```

##  Encoding Digester

```java
EncodingDigester digester(String algorithm, Encoding encoding);
```

 Returns an [encoding](../essentials/general-ideas.md#encoding) message digester for the given algorithm.

### Usage Example

```java
EncodingDigester digester = digester("SHA1", BASE64);
String hash = digester.digest("hello");
```

## Encoding Digester with Custom Character Set

```java
EncodingDigester digester(
    String algorithm, 
    Encoding encoding, 
    Charset charset
);
```

 Returns an [encoding](../essentials/general-ideas.md#encoding) message digester for the given algorithm and character set.

The character set parameter is used as the default encoding for the input message strings.

### Usage Example

```java
EncodingDigester digester = digester(
    "SHA1", BASE64, UTF_16
);
String hash = digester.digest("hello 👋🏻");
```

