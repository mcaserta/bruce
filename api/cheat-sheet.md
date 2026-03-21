# Cheat Sheet

Complete list of available builder methods and functional interfaces.
All static imports come from `com.mirkocaserta.bruce.Bruce`.

```java
// Supported encodings
public enum Encoding { HEX, BASE64, URL, MIME }

// ─── Keystore ───────────────────────────────────────────────────────────────
KeyStore keystore();
KeyStore keystore(String type);
KeyStore keystore(String location, char[] password);
KeyStore keystore(String location, String password);
KeyStore keystore(String location, char[] password, String type);
KeyStore keystore(String location, String password, String type);
KeyStore keystore(String location, char[] password, String type, String provider);
KeyStore keystore(String location, String password, String type, String provider);

// ─── Certificates ───────────────────────────────────────────────────────────
Certificate certificate(KeyStore keystore, String alias);

// ─── Keys ───────────────────────────────────────────────────────────────────
PublicKey  publicKey(KeyStore keystore, String alias);
PrivateKey privateKey(KeyStore keystore, String alias, char[] password);
PrivateKey privateKey(KeyStore keystore, String alias, String password);
Key        secretKey(KeyStore keystore, String alias, char[] password);
Key        secretKey(KeyStore keystore, String alias, String password);
KeyPair    keyPair(String algorithm, int keySize);
KeyPair    keyPair(String algorithm, String provider, int keySize);
KeyPair    keyPair(String algorithm, int keySize, SecureRandom random);
KeyPair    keyPair(String algorithm, String provider, int keySize, SecureRandom random);
byte[]     symmetricKey(String algorithm);
byte[]     symmetricKey(String algorithm, String provider);
String     symmetricKey(String algorithm, Encoding encoding);
String     symmetricKey(String algorithm, String provider, Encoding encoding);

// ─── Digests ────────────────────────────────────────────────────────────────
// Builder approach (preferred)
DigestBuilder digestBuilder();   // → .algorithm(...) .provider(...) .charset(...) .encoding(...) .build()

// Factory shortcut
Digester digester(String algorithm);
Digester digester(String algorithm, String provider);

// Digester methods  (bytes↔bytes  and  String↔String)
byte[]  Digester.digest(byte[]);
byte[]  Digester.digest(String);
byte[]  Digester.digest(String, Charset);
String  Digester.digestToString(byte[]);
String  Digester.digestToString(byte[], Encoding);
String  Digester.digestToString(String);
String  Digester.digestToString(String, Encoding);
String  Digester.digestToString(String, Charset, Encoding);
String  Digester.digestToString(Path);
String  Digester.digestToString(Path, Encoding);
String  Digester.digestToString(File);
String  Digester.digestToString(File, Encoding);

// ─── Signatures ─────────────────────────────────────────────────────────────
// Builder approach (preferred)
SignerBuilder   signerBuilder();    // → .key(pk) .keys(map) .algorithm(...) .provider(...) .charset(...) .encoding(...) .build() / .buildByKey()
VerifierBuilder verifierBuilder(); // → .key(pk) .keys(map) .algorithm(...) .provider(...) .charset(...) .encoding(...) .build() / .buildByKey()

// Signer methods
byte[]  Signer.sign(byte[]);
byte[]  Signer.sign(String);
byte[]  Signer.sign(String, Charset);
String  Signer.signToString(byte[]);
String  Signer.signToString(byte[], Encoding);
String  Signer.signToString(String);
String  Signer.signToString(String, Encoding);
String  Signer.signToString(String, Charset, Encoding);

// SignerByKey methods
byte[]  SignerByKey.sign(String keyId, byte[]);
byte[]  SignerByKey.sign(String keyId, String);
String  SignerByKey.signToString(String keyId, String);
String  SignerByKey.signToString(String keyId, String, Encoding);

// Verifier methods
boolean  Verifier.verify(byte[], byte[]);
boolean  Verifier.verify(String, byte[]);
boolean  Verifier.verify(String, Charset, byte[]);
boolean  Verifier.verify(String, String);
boolean  Verifier.verify(String, String, Encoding);
boolean  Verifier.verify(String, Charset, String, Encoding);

// VerifierByKey methods
boolean  VerifierByKey.verify(String keyId, byte[], byte[]);
boolean  VerifierByKey.verify(String keyId, String, String);
boolean  VerifierByKey.verify(String keyId, String, String, Encoding);

// ─── Asymmetric Ciphers ─────────────────────────────────────────────────────
AsymmetricEncryptorBuilder   encryptorBuilder();         // → .key(pubKey)  .algorithm(...) .provider(...) .charset(...) .encoding(...) .build()
AsymmetricDecryptorBuilder   decryptorBuilder();         // → .key(privKey) .algorithm(...) .provider(...) .charset(...) .encoding(...) .build()
AsymmetricEncryptorByKeyBuilder encryptorByKeyBuilder(); // → .keys(map) ...
AsymmetricDecryptorByKeyBuilder decryptorByKeyBuilder(); // → .keys(map) ...

// AsymmetricEncryptor methods
byte[]  AsymmetricEncryptor.encrypt(byte[]);
String  AsymmetricEncryptor.encryptToString(String);
String  AsymmetricEncryptor.encryptToString(String, Encoding);

// AsymmetricDecryptor methods
byte[]  AsymmetricDecryptor.decrypt(byte[]);
String  AsymmetricDecryptor.decryptToString(String);
String  AsymmetricDecryptor.decryptToString(String, Encoding);

// ─── Symmetric Ciphers ──────────────────────────────────────────────────────
SymmetricEncryptorBuilder      symmetricEncryptorBuilder();      // → .key(bytes) .keyAlgorithm(...) .algorithm(...) .provider(...) .charset(...) .encoding(...) .build()
SymmetricDecryptorBuilder      symmetricDecryptorBuilder();      // → same options
SymmetricEncryptorByKeyBuilder symmetricEncryptorByKeyBuilder(); // → .keyAlgorithm(...) .algorithm(...) ...
SymmetricDecryptorByKeyBuilder symmetricDecryptorByKeyBuilder(); // → same options

// SymmetricEncryptor methods
byte[]  SymmetricEncryptor.encrypt(byte[] iv, byte[] plaintext);
String  SymmetricEncryptor.encryptToString(String iv, String plaintext);
String  SymmetricEncryptor.encryptToString(String iv, String plaintext, Encoding);

// SymmetricDecryptor methods
byte[]  SymmetricDecryptor.decrypt(byte[] iv, byte[] ciphertext);
String  SymmetricDecryptor.decryptToString(String iv, String ciphertext);
String  SymmetricDecryptor.decryptToString(String iv, String ciphertext, Encoding);

// ─── Message Authentication Codes ───────────────────────────────────────────
MacBuilder macBuilder(); // → .key(...) .algorithm(...) .provider(...) .charset(...) .encoding(...) .build()

// Mac factory shortcut
Mac mac(Key key, String algorithm);
Mac mac(Key key, String algorithm, String provider);

// Mac methods
byte[]  Mac.get(byte[]);
byte[]  Mac.get(String);
byte[]  Mac.get(String, Charset);
String  Mac.getToString(byte[]);
String  Mac.getToString(byte[], Encoding);
String  Mac.getToString(String);
String  Mac.getToString(String, Encoding);
String  Mac.getToString(String, Charset, Encoding);
```

