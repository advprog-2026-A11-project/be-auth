import org.gradle.api.tasks.testing.Test
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification
import org.gradle.testing.jacoco.tasks.JacocoReport
import org.springframework.boot.gradle.tasks.run.BootRun
import java.io.ByteArrayOutputStream

plugins {
    java
    id("jacoco")
    id("org.springframework.boot") version "3.5.10"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.sonarqube") version "7.1.0.6387"
}

group = "id.ac.ui.cs.advprog"
version = "0.0.1-SNAPSHOT"
description = "auth"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

repositories {
    mavenCentral()
}

val coverageExclusions = listOf(
    "**/AuthApplication*",
    "**/dto/**",
    "**/config/OpenApiConfig*",
    "**/exception/GlobalExceptionHandler*",
    "**/model/UserProfile*",
    "**/security/CurrentUserProvider*",
    "**/service/HttpSupabaseAuthClient*",
    "**/service/AuthLoginService*",
    "**/service/PkceStateStore*",
    "**/service/RevokedTokenStore*",
    "**/service/SupabaseGoogleSsoService*",
    "**/service/SupabaseAuthClient*",
    "**/service/UserProfileService*"
)

sonarqube {
        properties {
                property("sonar.projectKey", "advprog-2026-A11-project_be-auth")
                property("sonar.organization", "adpro-a-kelompok-11")
                property(
                    "sonar.coverage.exclusions",
                    coverageExclusions.joinToString(","))
        }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.security:spring-security-oauth2-jose")
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.6")
    runtimeOnly("org.postgresql:postgresql")
    compileOnly("org.projectlombok:lombok")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    annotationProcessor("org.projectlombok:lombok")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("com.h2database:h2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    filter {
        excludeTestsMatching("*FunctionalTest")
    }
}

val functionalTest by tasks.registering(Test::class) {
    description = "Runs functional smoke tests."
    group = "verification"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter(tasks.named("test"))
    filter {
        includeTestsMatching("*FunctionalTest")
    }
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.named("test"))
    classDirectories.setFrom(
        sourceSets.main.get().output.asFileTree.matching {
            exclude(coverageExclusions)
        }
    )
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
    dependsOn(tasks.named("jacocoTestReport"))
    classDirectories.setFrom(
        sourceSets.main.get().output.asFileTree.matching {
            exclude(coverageExclusions)
        }
    )
    violationRules {
        rule {
            limit {
                counter = "LINE"
                value = "COVEREDRATIO"
                minimum = "1.0".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                value = "COVEREDRATIO"
                minimum = "1.0".toBigDecimal()
            }
        }
    }
}

tasks.named("check") {
    dependsOn(tasks.named("jacocoTestCoverageVerification"))
    dependsOn(functionalTest)
}

fun configuredServerPort(): Int {
    val envPort = System.getenv("SERVER_PORT")?.toIntOrNull()
    if (envPort != null) {
        return envPort
    }

    val appProperties = file("src/main/resources/application.properties")
    val defaultPort = Regex("""server\.port=\$\{SERVER_PORT:(\d+)}""")
        .find(appProperties.readText())
        ?.groupValues
        ?.get(1)
        ?.toIntOrNull()

    return defaultPort ?: 8081
}

fun runAndCapture(vararg command: String): String {
    val process = ProcessBuilder(*command)
        .redirectErrorStream(true)
        .start()
    val output = process.inputStream.bufferedReader().use { it.readText() }
    process.waitFor()
    return output.trim()
}

fun releasePortIfBusy(port: Int) {
    val isWindows = System.getProperty("os.name").lowercase().contains("win")
    val pidOutput = if (isWindows) {
        runAndCapture(
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetTCPConnection -LocalPort $port -State Listen | " +
                "Select-Object -ExpandProperty OwningProcess -Unique"
        )
    } else {
        runAndCapture("bash", "-lc", "lsof -ti tcp:$port -sTCP:LISTEN")
    }

    pidOutput
        .lineSequence()
        .map(String::trim)
        .filter(String::isNotEmpty)
        .distinct()
        .forEach { pid ->
            logger.lifecycle("Stopping process $pid that is already using port $port")
            if (isWindows) {
                ProcessBuilder("taskkill", "/PID", pid, "/F")
                    .redirectErrorStream(true)
                    .start()
                    .waitFor()
            } else {
                ProcessBuilder("kill", "-9", pid)
                    .redirectErrorStream(true)
                    .start()
                    .waitFor()
            }
        }
}

tasks.named<BootRun>("bootRun") {
    doFirst {
        releasePortIfBusy(configuredServerPort())
    }
}
