// Чисте криптографічне ядро: жодних залежностей від Android SDK.
// Тестується на будь-якій JVM за спільними векторами shared/test-vectors/.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

dependencies {
    implementation(libs.bouncycastle.prov)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit5.api)
    testImplementation(libs.junit5.params)
    testRuntimeOnly(libs.junit5.engine)
    // Gradle 9 більше не додає launcher до classpath тестів автоматично
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    // Шлях до спільних тестових векторів монорепозиторію
    systemProperty("vectors.dir", rootDir.resolve("../shared/test-vectors").absolutePath)
}
