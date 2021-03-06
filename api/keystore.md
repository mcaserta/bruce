# Key Stores

For managing Java key stores, I suggest using [KeyStore Explorer](https://keystore-explorer.org/).

## Default

```java
KeyStore keystore();
```

 Returns the default key store using configuration from the following system properties:

* `javax.net.ssl.keyStore`
* `javax.net.ssl.keyStorePassword`

The key store location supports the following protocols:

* `classpath:`
* `http:`
* `https:`
* `file:`

  If no protocol is specified, `file` is assumed. The default key store type is `PKCS12`.

### Usage Example

```java
KeyStore keystore = keystore();
```

##  Default with Type

```java
KeyStore keystore(String type);
```

 Same as [above](keystore.md#default) but the key store type can be specified. For instance, valid types include: `JKS`, `PKCS12`.

### Usage Example

```java
KeyStore keystore = keystore("JKS");
```

## From Location

```java
KeyStore keystore(
    String location, 
    char[] password
);
```

Loads a key store from the given location.

The location parameter supports the protocols described in the [default key store](keystore.md#default) api method.

The key store is opened with the given password.

The key store type is assumed to be the default: `PKCS12`.

### Usage Example

```java
// load key store from classpath
KeyStore keystore = keystore(
    "classpath:keystore.p12", 
    "password".toCharArray()
);
```

```java
// load key store from file
KeyStore keystore = keystore(
    "file:/etc/myapp/keystore.p12", 
    "password".toCharArray()
);
```

```java
// load key store from https
KeyStore keystore = keystore(
    "https://acme.com/sec/keystore.p12", 
    "password".toCharArray()
);
```

## From Location with Type

```java
KeyStore keystore(
    String location, 
    char[] password, 
    String type
);
```

Same as in [from location](keystore.md#from-location) but allows you to specify a key store type. For instance, valid types include: `JKS`, `PKCS12`.

### Usage Examples

```java
// use JKS as the key store type
KeyStore keystore = keystore(
    "classpath:keystore.jks", 
    "password".toCharArray(), 
    "JKS"
);
```

```java
// use PKCS12 as the key store type
KeyStore keystore = keystore(
    "classpath:keystore.p12", 
    "password".toCharArray(), 
    "PKCS12"
);
```

