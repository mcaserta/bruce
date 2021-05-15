# General Ideas

Some general ideas apply to all functionalities in Bruce.

Most methods allow choosing the most appropriate version through [overloading](https://www.w3schools.com/java/java_methods_overloading.asp).

## Static Imports

Static imports are assumed through all examples. Instead of:

```text
import com.mirkocaserta.bruce.Bruce;

Digester digester = Bruce.digester("SHA1");
```

the examples assume:

```text
import static com.mirkocaserta.bruce.Bruce.digester;

Digester digester = digester("SHA1");
```

You are of course free not to use static imports. I personally like them as the code looks a bit tidier.

## Encoding

### Raw byte arrays

At the most basic level, computers work with bits. In Java, you can work at the bit level, but the most basic form of storage for encrypted data is the byte. At low level, Java cryptography usually works on arrays of bytes, such as:

```text
public static final byte[] MESSAGE_SHA1 = new byte[]{
        (byte) 0x6f, (byte) 0x9b, (byte) 0x9a, (byte) 0xf3,
        (byte) 0xcd, (byte) 0x6e, (byte) 0x8b, (byte) 0x8a,
        (byte) 0x73, (byte) 0xc2, (byte) 0xcd, (byte) 0xce,
        (byte) 0xd3, (byte) 0x7f, (byte) 0xe9, (byte) 0xf5,
        (byte) 0x92, (byte) 0x26, (byte) 0xe2, (byte) 0x7d
};

Digester digester = digester("SHA1");
byte[] hash = digester.digest("message".getBytes(StandardCharsets.UTF_8));
```

The `MESSAGE_SHA1` and `hash` byte arrays are identical. You can easily see however how this is not always a very practical representation format. You cannot directly use this value in a text file, an email message or a JSON payload.

### Encodings

For these reasons all methods that work with raw byte arrays also have an overloaded version that supports different encodings.

```text
EncodingDigester digester = digester("SHA1", BASE64);
String hash = digester.digest("message");
```

The hash String is going to look like this, as it gets base64 encoded: `"b5ua881ui4pzws3O03/p9ZIm4n0="`.

{% hint style="info" %}
| Base64, email and 7 bits |
| :--- |
| SMTP, the protocol the Internet uses for sending emails, - in its original form - was designed to transport 7-bit ASCII characters only. Base64 works around this limitation by using characters that fit in a 7-bit space. |
{% endhint %}

{% hint style="warning" %}
## Cipher encoding vs charset encoding

Please do not confuse the cipher encoding with the message character encoding. They are different things in the API parameters, and they are different Java types in Bruce so any confusion results in a compiler error.
{% endhint %}

## Providers

All methods allow specifying an optional JCA provider.

For instance, to use the [Bouncy Castle](https://www.bouncycastle.org/java.html) provider with a digester:

```text
// use the Bouncy Castle provider
EncodingDigester digester = digester("SHA1", "BC", HEX);
```

{% hint style="warning" %}
Do not forget to add the appropriate provider jar to the classpath for this to work.
{% endhint %}

## Error Handling

There is a single exception in Bruce that wraps all kinds of errors: the `BruceException`. As it is a `RuntimeException`, you are not forced to catch it.

Initialization and configuration errors are raised as soon as possible.

