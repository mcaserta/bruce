[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mcaserta_bruce&metric=alert_status)](https://sonarcloud.io/dashboard?id=mcaserta_bruce)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=mcaserta_bruce&metric=security_rating)](https://sonarcloud.io/dashboard?id=mcaserta_bruce)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=mcaserta_bruce&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=mcaserta_bruce)

# Welcome

Bruce is an opinionated, ergonomic, lightweight, pure Java wrapper around the Java Cryptography API.

## Features

- All functionality is exposed through the `Bruce` entry point class. Just type `Bruce.` and let your IDE's autocomplete
  do the rest.
- No checked exceptions cluttering your code.
- No transitive dependencies. Zero. Zilch.
- Support for different encodings: [Base64](https://en.wikipedia.org/wiki/Base64)
  , [Url](https://en.wikipedia.org/wiki/Percent-encoding), [Mime](https://en.wikipedia.org/wiki/MIME)
  , [Hex](https://en.wikipedia.org/wiki/Hexadecimal).
- Out of the box support for:
    - key stores
    - public, private and secret keys
    - certificates
    - digital signatures
    - symmetric and asymmetric encryption
    - message digesters
    - message authentication codes
    - custom providers such as [Bouncy Castle](https://www.bouncycastle.org/java.html)
- Massively unit tested<!-- TODO: and documented -->.
- Open Source: you don't need to trust Bruce: you can see for yourself if you like what Bruce does.

## Requirements

- Java 15

## How to Bruce

### With Apache Maven

```xml

<dependency>
    TODO
</dependency>
```

### With Gradle

TODO

### Without Apache Maven

Grab the latest release from [here](TODO).

## Keystore

TODO

## Keys

TODO

## Certificate

TODO

## Signature

### With a Single Key

TODO

### With Multiple Keys

TODO

## Symmetric Encription

TODO

## Asymmetric Encryption

TODO

## Message Digests

TODO

## Message Authentication Codes

TODO

## License

Bruce is licensed under the Apache License, Version 2.0.
