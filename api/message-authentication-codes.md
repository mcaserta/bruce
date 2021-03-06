# Message Authentication Codes

## MAC

```java
Mac mac(Key key, String algorithm);
```

 Returns an interface for producing message authentication codes.

### Usage Example

```java
KeyStore keystore = keystore("classpath:/keystore.p12", "password".toCharArray(), "PKCS12");
Key key = secretKey(keystore, "hmac", "password".toCharArray());

Mac alice = mac(key, "HmacSHA1");
Mac bob = mac(key, "HmacSHA1");

byte[] message = "Hello there".getBytes(UTF_8);
byte[] aliceMac = alice.get(message);
byte[] bobMac = bob.get(message);
assertArrayEquals(aliceMac, bobMac);
```

##  Encoding MAC

```text
EncodingMac mac(
    Key key, 
    String algorithm, 
    Encoding encoding, 
    Charset charset
);
```

 Returns an interface for producing encoded message authentication codes. The character set refers to the plain text message string encoding.

### Usage Example

```java
KeyStore keystore = keystore("classpath:/keystore.p12", "password", "PKCS12");
Key key = secretKey(keystore, "hmac", "password");

EncodingMac alice = mac(key, "HmacSHA1", BASE64, UTF_8);
EncodingMac bob = mac(key, "HmacSHA1", BASE64, UTF_8);

String message = "Hello there";
String aliceMac = alice.get(message);
String bobMac = bob.get(message);
assertEquals(aliceMac, bobMac);
```

