# Features

- All cryptographic operations are exposed through a small set of entry points:
  - `Bruce` — builder factories (`cipherBuilder()`, `signerBuilder()`,
    `verifierBuilder()`, `digestBuilder()`, `macBuilder()`)
  - `Keystores` — keystore loading, key and certificate retrieval, key
    generation
  - `Bytes` — universal I/O type for passing data in and getting results out
- No checked exceptions cluttering your code.
- No transitive dependencies. Zero. Zilch.
- Out of the box support for:
  - key stores
  - public, private and secret keys
  - certificates
  - digital signatures
  - symmetric and asymmetric encryption
  - message digesters
  - message authentication codes
  - different encodings: [Base64](https://en.wikipedia.org/wiki/Base64),
    [Url](https://en.wikipedia.org/wiki/Percent-encoding),
    [Mime](https://en.wikipedia.org/wiki/MIME),
    [Hex](https://en.wikipedia.org/wiki/Hexadecimal)
  - custom providers such as
    [Bouncy Castle](https://www.bouncycastle.org/java.html)
- Massively unit tested and documented.
- Open Source: you don't need to trust Bruce: you can
  [see for yourself](https://github.com/mcaserta/bruce) if you like what Bruce
  does.
