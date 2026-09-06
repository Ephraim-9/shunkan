// Shunkan Android project settings

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// This block is `dependencyResolutionManagement`, not `dependencyResolution`.
// The wrong name is not a warning — Kotlin DSL fails to compile the script, so
// evaluation aborted before anything else was attempted and the module could
// not even be opened.
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Shunkan"
include(":app")
