group = "de.torsm"
version = "1.0"

plugins {
    kotlin("jvm") version "1.9.21"
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
    implementation("io.ktor:ktor-network:2.3.6")
    implementation("ch.qos.logback:logback-classic:1.4.11")
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
}

tasks.test {
    useJUnitPlatform()
}
