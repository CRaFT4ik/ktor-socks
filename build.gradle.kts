group = "de.torsm"
version = "1.0"

plugins {
    kotlin("jvm") version "1.9.22"
}

kotlin {
    explicitApi()
    jvmToolchain(17)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("io.ktor:ktor-network:2.3.12")
    implementation("ch.qos.logback:logback-classic:1.4.14")
    // dnsjava: async DNS resolver used by SOCKSHandshake to avoid blocking a JVM thread on
    // InetAddress.getByName when a dead host is requested. BSD-3-Clause, ~450 KB, no native code.
    implementation("dnsjava:dnsjava:3.6.5")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:1.7.3")
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.1")
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("-Xmx768m")
}
