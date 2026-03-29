# Certificates

All methods below are available as static imports from
`com.mirkocaserta.bruce.Keystores`.

## Certificate

```java
Certificate certificate(KeyStore keystore, String alias);
```

Loads a certificate from a given key store.

### Usage example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
Certificate certificate = certificate(keystore, "alice");
```

## Certificate Format Conversions

Bruce supports certificate format conversions without Bouncy Castle.

```java
// PEM -> Certificate (X.509)
Certificate certificateFromPem(String pem);

// DER -> Certificate (X.509)
Certificate certificateFromDer(byte[] der);

// Certificate -> PEM
String certificateToPem(Certificate certificate);

// Certificate -> DER
byte[] certificateToDer(Certificate certificate);

// Generic PEM <-> DER conversion helpers
byte[] pemToDer(String pem);
String derToPem(byte[] der, PemType type);
```

### Usage example

```java
KeyStore ks = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
Certificate cert = certificate(ks, "test");

String pem = certificateToPem(cert);
byte[] der = certificateToDer(cert);

Certificate fromPem = certificateFromPem(pem);
Certificate fromDer = certificateFromDer(der);

assertEquals(cert, fromPem);
assertEquals(cert, fromDer);
```
