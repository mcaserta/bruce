# Certificates

## Certificate

```java
Certificate certificate(
    KeyStore keystore, 
    String alias
);
```

 Loads a certificate from a given key store.

### Usage example

```java
KeyStore keystore = keystore("classpath:keystore.p12", "password".toCharArray(), "PKCS12");
Certificate certificate = certificate(keystore, "alice");
```

 

