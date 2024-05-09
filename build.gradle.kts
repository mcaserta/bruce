plugins {
    java
    id("org.sonarqube") version "5.0.0.4638"
    jacoco
    `maven-publish`
    id("com.diffplug.spotless") version "6.25.0"
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.78")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testImplementation("org.mockito:mockito-core:5.11.0")
}

group = "com.github.mcaserta"
version = "1.0.6-SNAPSHOT"
description = "An ergonomic wrapper around the JCA api"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
    withJavadocJar()
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("myLibrary") {
            from(components["java"])
        }
    }
}

sonarqube {
    properties {
        property("sonar.projectKey", "mcaserta_bruce")
        property("sonar.organization", "mcaserta")
        property("sonar.host.url", "https://sonarcloud.io")
    }
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
    }
}

spotless {
    java {
        googleJavaFormat("1.22.0").reflowLongStrings().formatJavadoc(true)
        removeUnusedImports()
        formatAnnotations()
    }
}

