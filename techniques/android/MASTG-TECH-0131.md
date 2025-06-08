---
title: Software Composition Analysis (SCA) of Android Dependencies at Build Time
platform: android
---

Modern Android applications rely heavily on third-party libraries, making dependency security a critical concern. Software Composition Analysis (SCA) tools inspect dependency metadata, such as package names and versions, and compare it against public vulnerability databases, like the National Vulnerability Database (NVD), to help identify known vulnerabilities.

In Android development, dependencies are resolved and compiled during the build process and eventually become part of the app's DEX files. Therefore, it is essential to scan dependencies as they appear in the build environment, not just within the final APK. This approach ensures that all libraries, including transitive ones, are analyzed accurately.

Since dependencies are declared and resolved in the build environment, integrating SCA tools into the build system is the most effective strategy. [Gradle](https://developer.android.com/build/dependencies) is especially relevant in this context because it is the default build tool used by Android Studio and the most common dependency management system in Android projects.

## Using @MASTG-TOOL-0131

To test for dependencies with known vulnerabilities, integrate the dependency-check plugin into the Android project via Gradle. The Android project's dependencies are located in the directory `~/.gradle/caches/modules-2/files-2.1` and not in the Android project directory.

Before running the scan, obtain an API key for NVD to retrieve the latest CVE information. You can request the API key to access the NVD API from <https://nvd.nist.gov/developers/request-an-api-key>.

!!! info

    In recent versions of @MASTG-TOOL-0131 (up to and including version 12.1.1 at the time of writing), you may encounter multiple 'NoSuchMethodError' messages related to `ZipFile.builder()`. This can be resolved by [pinning the version of `org.apache.commons:commons-compress`](https://github.com/dependency-check/DependencyCheck/issues/7405#issuecomment-2785588330).

In the `build.gradle` of `Module: app` (not the project `build.gradle` file), add the `dependencycheck` dependency in the latest version and the `dependencyCheck` configuration:

```groovy
plugins {
    ...
    id("org.owasp.dependencycheck") version "12.1.1" // This is the latest version at the time of writing, please update accordingly
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

**Suppressing False Positives:**

If there are dependencies that you want to suppress because they are false positives or are not included in the APK but might be necessary for building the APK, you can use a suppression file. The following `suppression.xml` would exclude all vulnerabilities from the package URLs `pkg:maven/io.grpc/grpc.*` and `pkg:maven/io.netty/netty.*`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <notes><![CDATA[
        This suppresses false positives identified on grpc that are not added into the APK.
        ]]></notes>
        <packageUrl regex="true">^pkg:maven/io\.grpc/grpc.*</packageUrl>
        <vulnerabilityName regex="true">.*</vulnerabilityName>
    </suppress>

    <suppress>
        <notes><![CDATA[
        This suppresses false positives identified on netty that are not added into the APK.
        ]]></notes>
        <packageUrl regex="true">^pkg:maven/io\.netty/netty.*</packageUrl>
        <vulnerabilityName regex="true">.*</vulnerabilityName>
    </suppress>

</suppressions>
```

To use the `suppression.xml` file, add the following line to your `build.gradle.kts` file:

```java
dependencyCheck {

    formats = listOf("HTML", "XML", "JSON") // Generate reports in HTML, JSON and XML format

    suppressionFile = "suppression.xml"
    ...
```

Further examples of suppressing false positives can be found [here](https://jeremylong.github.io/DependencyCheck/general/suppression.html).
