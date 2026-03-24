# Getting Started

## Requirements

Bruce requires Java 21. That's it. That's the whole requirement.

You also need to understand basic cryptography concepts. If you need a
refresher, I suggest
[Cryptography Engineering](https://www.schneier.com/books/cryptography-engineering/)
and
[Applied Cryptography](https://www.schneier.com/books/applied-cryptography/),
both by [Bruce Schneier](https://www.schneier.com/).

## Setup

Bruce 2.0.0 is available on [Maven Central](https://central.sonatype.com/artifact/com.mirkocaserta.bruce/bruce/2.0.0/overview).

### Maven

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.mirkocaserta.bruce</groupId>
    <artifactId>bruce</artifactId>
    <version>2.0.0</version>
</dependency>
```

### Gradle (Kotlin DSL)

Add the following to your `build.gradle.kts`:

```kotlin
implementation("com.mirkocaserta.bruce:bruce:2.0.0")
```

### Gradle (Groovy DSL)

Add the following to your `build.gradle`:

```groovy
implementation 'com.mirkocaserta.bruce:bruce:2.0.0'
```

### Scala SBT

```scala
libraryDependencies += "com.mirkocaserta.bruce" % "bruce" % "2.0.0"
```

### Apache Ivy

```xml
<dependency org="com.mirkocaserta.bruce" name="bruce" rev="2.0.0"/>
```
