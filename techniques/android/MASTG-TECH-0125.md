---
title: Software Composition Analysis (SCA) of Android Dependencies during the Build
platform: android
---

For Android both popular build automation tools, are also dependency managers:

- [Gradle](https://developer.android.com/build/dependencies) and
- Maven.

Gradle is the default build automation tool in Android Studio and this technique will focus on it.

Tools like @MASTG-TOOL-0116 can be integrated into the build environments, where they can inspect the build configuration files or the actual `.jar` files and their metadata, such as the version, to identify dependencies. Once identified such tools will identify known vulnerabilities in the dependencies by comparing them to a vulnerability database (like the National Vulnerability Database, NVD).

In order to test for dependencies with known vulnerabilities, we need to integrate the @MASTG-TOOL-0116 plugin into the Android project via Gradle. The dependencies of the Android project are located in the following directory `~/.gradle/caches/modules-2/files-2.1`, and not in the Android Project directory.

The dependencies will be integrated into the project during run-time, but will also be modified and compiled into the DEX file(s) of the APK. therefore we need to scan dependencies in Android Studio and cannot scan the APK.

Before we can run the scan, you will need to obtain an API key for NVD, which is used to retrieve the latest CVE information. The API Key to access the NVD API can be requested from <https://nvd.nist.gov/developers/request-an-api-key>.

In the `build.gradle` of `Module: app` (not the project `build.gradle` file), add the `dependencycheck` dependency in the latest version and the `dependencyCheck` configuration:

```groovy
plugins {
    ...
    id("org.owasp.dependencycheck") version "10.0.4" // This is the latest version at the time of writing, please update accordingly
}

dependencyCheck {

    formats = listOf("HTML", "XML", "JSON") // Generate reports in HTML, JSON and XML format
    
    nvd {
        apiKey = "<YOUR NVD API KEY>"
        delay = 16000
    }

}
```

Open a terminal in Android Studio and execute the following command:

```bash
$ ./gradlew dependencyCheckAnalyze
...
BUILD SUCCESSFUL in 6s
1 actionable task: 1 executed
```

The report was generated in 3 different formats (HTML, JSON and XML) and can be found in the project directory in `app/build/reports`.
