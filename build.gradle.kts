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
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.1")
}

tasks.test {
    useJUnitPlatform()
}
