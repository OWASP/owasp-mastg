---
title: Software Composition Analysis (SCA) of Android Dependencies at Build Time
platform: android
---

Although other tools like Maven exist, we will focus on [Gradle](https://developer.android.com/build/dependencies), the default build automation and dependency management tool in Android Studio.

Tools like @MASTG-TOOL-0131 can be integrated into build environments where they can inspect build configuration files, actual `.jar` files, and their metadata (e.g., version) to identify dependencies. These tools then compare the dependencies to a vulnerability database, such as the National Vulnerability Database (NVD), to identify known vulnerabilities.

To test for dependencies with known vulnerabilities, integrate the @MASTG-TOOL-0131 plugin into the Android project via Gradle. The Android project's dependencies are located in the directory `~/.gradle/caches/modules-2/files-2.1` and not in the Android project directory.

The dependencies are integrated into the project at runtime but are also modified and compiled into the DEX file(s) of the APK; therefore, we must scan the dependencies in Android Studio, not the APK.

Before running the scan, obtain an API key for NVD to retrieve the latest CVE information. You can request the API key to access the NVD API from <https://nvd.nist.gov/developers/request-an-api-key>.

!!!info

    In recent versions of @MASTG-TOOL-0131 (up to and including 12.1.1 at the time of writing), you may encounter multiple 'NoSuchMethodError' messages relating to 'ZipFile.builder()'. This can be mitigated by [pinning the  version of `org.apache.commons:commons-compress`](https://github.com/dependency-check/DependencyCheck/issues/7405#issuecomment-2785588330).

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

In case there are dependencies you want to suppress, either as they are false positives or as they are not included into the APK, but might be needed to build the APK, you can use a suppression file. The following file would exclude all vulnerabilities from the package URLs `pkg:maven/io.grpc/grpc.*` and `pkg:maven/io.netty/netty.*`:

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

```json
dependencyCheck {

    formats = listOf("HTML", "XML", "JSON") // Generate reports in HTML, JSON and XML format

    suppressionFile = "suppression.xml"
    ...
```

Further examples of suppressing false positives can be found [here](https://jeremylong.github.io/DependencyCheck/general/suppression.html).
