# Key Stores

For managing Java key stores, I suggest using
[KeyStore Explorer](https://keystore-explorer.org/).

All methods below are available as static imports from
`com.mirkocaserta.bruce.Keystores`.

## Default

```java
KeyStore keystore();
```

Returns the default key store using configuration from the following system
properties:

- `javax.net.ssl.keyStore`
- `javax.net.ssl.keyStorePassword`

The key store location supports the following protocols:

- `classpath:`
- `http:`
- `https:`
- `file:`

If no protocol is specified, `file` is assumed. The default key store type is
`PKCS12`.

### Usage Example

```java
KeyStore keystore = keystore();
```

## Default with Type

```java
KeyStore keystore(String type);
```

Same as [above](#default) but the key store type can be specified. For instance,
valid types include: `JKS`, `PKCS12`.

### Usage Example

```java
KeyStore keystore = keystore("JKS");
```

## From Location

```java
KeyStore keystore(String location, char[] password);
KeyStore keystore(String location, String password);
```

Loads a key store from the given location.

The location parameter supports the protocols described in the
[default key store](#default) section.

The key store is opened with the given password. The key store type is assumed
to be the default: `PKCS12`.

### Usage Examples

```java
// load key store from classpath
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray());

// load key store from file
KeyStore keystore = keystore("file:/etc/myapp/keystore.p12", "password".toCharArray());

// load key store from https
KeyStore keystore = keystore("https://acme.com/sec/keystore.p12", "password".toCharArray());

// convenience String password overload
KeyStore keystore = keystore("classpath:keystore.p12", "password");
```

## From Location with Type

```java
KeyStore keystore(String location, char[] password, String type);
KeyStore keystore(String location, String password, String type);
```

Same as [from location](#from-location) but allows you to specify a key store
type.

### Usage Examples

```java
// use JKS as the key store type
KeyStore keystore = keystore("classpath:keystore.jks", "password".toCharArray(), "JKS");

// use PKCS12 as the key store type
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
```

## From Location with Type and Provider

```java
KeyStore keystore(String location, char[] password, String type, String provider);
KeyStore keystore(String location, String password, String type, String provider);
```

Same as above but allows specifying an explicit JCA provider.

### Usage Example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12", "BC");
```

## Serialization

```java
byte[] keystoreToBytes(KeyStore keystore, char[] password);
byte[] keystoreToBytes(KeyStore keystore, String password);

String keystoreToString(KeyStore keystore, char[] password, Bruce.Encoding encoding);
String keystoreToString(KeyStore keystore, String password, Bruce.Encoding encoding);

void keystoreToFile(KeyStore keystore, char[] password, Path path);
void keystoreToFile(KeyStore keystore, String password, Path path);
void keystoreToFile(KeyStore keystore, char[] password, File file);
void keystoreToFile(KeyStore keystore, String password, File file);
```

Serializes an in-memory key store so you can persist it in different forms:

- raw bytes for transport or custom storage
- encoded text using `HEX`, `BASE64`, `URL`, or `MIME`
- direct file output to `Path` or `File`

### Usage Examples

```java
KeyStore ks = keystore("classpath:keystore.p12", "password");

byte[] raw = keystoreToBytes(ks, "password");
String base64 = keystoreToString(ks, "password", Bruce.Encoding.BASE64);

keystoreToFile(ks, "password", Path.of("/tmp/keystore-copy.p12"));
keystoreToFile(ks, "password", new File("/tmp/keystore-copy-2.p12"));
```

