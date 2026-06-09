pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "authapp"

include(":core-crypto")

// Модуль :app потребує Android SDK. Підключаємо його лише коли SDK доступний,
// щоб криптоядро можна було збирати й тестувати на будь-якій машині (CI, JVM).
val hasAndroidSdk = System.getenv("ANDROID_HOME") != null ||
    System.getenv("ANDROID_SDK_ROOT") != null ||
    file("local.properties").let { it.exists() && it.readText().contains("sdk.dir") }
if (hasAndroidSdk) {
    include(":app")
} else {
    logger.lifecycle("Android SDK не знайдено: модуль :app пропущено, доступний лише :core-crypto")
}
