# Android Code Quality and Build Settings

## Overview

### App Signing

Android requires all APKs to be digitally signed with a certificate before they are installed or run. The digital signature is used to verify the owner's identity for application updates. This process can prevent an app from being tampered with or modified to include malicious code.

When an APK is signed, a public-key certificate is attached to it. This certificate uniquely associates the APK with the developer and the developer's private key. When an app is being built in debug mode, the Android SDK signs the app with a debug key created specifically for debugging purposes. An app signed with a debug key is not meant to be distributed and won't be accepted in most app stores, including the Google Play Store.

The [final release build](https://developer.android.com/studio/publish/app-signing.html "Android Application Signing") of an app must be signed with a valid release key. In Android Studio, the app can be signed manually or via creation of a signing configuration that's assigned to the release build type.

Prior Android 9 (API level 28) all app updates on Android need to be signed with the same certificate, so a [validity period of 25 years or more is recommended](https://developer.android.com/studio/publish/app-signing#considerations "Android Signing Considerations"). Apps published on Google Play must be signed with a key that that has a validity period ending after October 22th, 2033.

Three APK signing schemes are available:

- JAR signing (v1 scheme),
- APK Signature Scheme v2 (v2 scheme),
- APK Signature Scheme v3 (v3 scheme).

The v2 signature, which is supported by Android 7.0 (API level 24) and above, offers improved security and performance compared to v1 scheme.
The V3 signature, which is supported by Android 9 (API level 28) and above, gives apps the ability to change their signing keys as part of an APK update. This functionality assures compatibility and apps continuous availability by allowing both the new and the old keys to be used. Note that it is only available via apksigner at the time of writing.

For each signing scheme the release builds should always be signed via all its previous schemes as well.

### Third-Party Libraries

Android apps often make use of third party libraries. These third party libraries accelerate development as the developer has to write less code in order to solve a problem. There are two categories of libraries:

- Libraries that are not (or should not) be packed within the actual production application, such as `Mockito` used for testing and libraries like `JavaAssist` used to compile certain other libraries.
- Libraries that are packed within the actual production application, such as `Okhttp3`.

These libraries can lead to unwanted side-effects:

- A library can contain a vulnerability, which will make the application vulnerable. A good example are the versions of `OKHTTP` prior to 2.7.5 in which TLS chain pollution was possible to bypass SSL pinning.
- A library can no longer be maintained or hardly be used, which is why no vulnerabilities are reported and/or fixed. This can lead to having bad and/or vulnerable code in your application through the library.
- A library can use a license, such as LGPL2.1, which requires the application author to provide access to the source code for those who use the application and request insight in its sources. In fact the application should then be allowed to be redistributed with modifications to its sourcecode. This can endanger the intellectual property (IP) of the application.

Please note that this issue can hold on multiple levels: When you use webviews with JavaScript running in the webview, the JavaScript libraries can have these issues as well. The same holds for plugins/libraries for Cordova, React-native and Xamarin apps.

### Memory Corruption Bugs

Android applications run on a VM where most of the memory corruption issues have been taken care off. This does not mean that there are no memory corruption bugs. Take [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") for instance, which is related to serialization issues using Parcels. Next, in native code, we still see the same issues as we explained in the general memory corruption section. Last, we see memory bugs in supporting services, such as with the Stagefright attack as shown [at BlackHat](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefright").

Memory leaks are often an issue as well. This can happen for instance when a reference to the `Context` object is passed around to non-`Activity` classes, or when you pass references to `Activity` classes to your helper classes.

### Binary Protection Mechanisms

Detecting the presence of [binary protection mechanisms](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) heavily depend on the language used for developing the application.

In general all binaries should be tested, which includes both the main app executable as well as all libraries/dependencies. However, on Android we will focus on native libraries since the main executables are considered safe as we will see next.

Android optimizes its Dalvik bytecode from the app DEX files (e.g. classes.dex) and generates a new file containing the native code, usually with an .odex, .oat extension. This [Android compiled binary](0x05b-Basic-Security_Testing.md#compiled-app-binary) is wrapped using the [ELF format](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html) which is the format used by Linux and Android to package assembly code.

The app's [NDK native libraries](0x05b-Basic-Security_Testing.md#native-libraries) also [use the ELF format](https://developer.android.com/ndk/guides/abis).

- [**PIE (Position Independent Executable)**](0x04h-Testing-Code-Quality.md#position-independent-code):
  - Since Android 7.0 (API level 24), PIC compilation is [enabled by default](https://source.android.com/devices/tech/dalvik/configure) for the main executables.
  - With Android 5.0 (API level 21), support for non-PIE enabled native libraries was [dropped](https://source.android.com/security/enhancements/enhancements50) and since then, PIE is [enforced by the linker](https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=430).
- [**Memory management**](0x04h-Testing-Code-Quality.md#memory-management):
  - Garbage Collection will simply run for the main binaries and there's nothing to be checked on the binaries themselves.
  - Garbage Collection does not apply to Android native libraries. The developer is responsible for doing proper [manual memory management](0x04h-Testing-Code-Quality.md#manual-memory-management). See ["Memory Corruption Bugs (MSTG-CODE-8)"](#memory-corruption-bugs-mstg-code-8).
- [**Stack Smashing Protection**](0x04h-Testing-Code-Quality.md#stack-smashing-protection):
  - Android apps get compiled to Dalvik bytecode which is considered memory safe (at least for mitigating buffer overflows). Other frameworks such as Flutter will not compile using stack canaries because of the way their language, in this case Dart, mitigates buffer overflows.
  - It must be enabled for Android native libraries but it might be difficult to fully determine it.
    - NDK libraries should have it enabled since the compiler does it by default.
    - Other custom C/C++ libraries might not have it enabled.

Learn more:

- [Android executable formats](https://lief-project.github.io/doc/latest/tutorials/10_android_formats.html)
- [Android runtime (ART)](https://source.android.com/devices/tech/dalvik/configure#how_art_works)
- [Android NDK](https://developer.android.com/ndk/guides)
- [Android linker changes for NDK developers](https://android.googlesource.com/platform/bionic/+/master/android-changes-for-ndk-developers.md)

### Debuggable Apps

Debugging is an essential process for developers to identify and fix errors or bugs in their Android app. By using a debugger, developers can select the device to debug their app on and set breakpoints in their Java, Kotlin, and C/C++ code. This allows them to analyze variables and evaluate expressions at runtime, which helps them to identify the root cause of many issues. By debugging their app, developers can improve the functionality and user experience of their app, ensuring that it runs smoothly without any errors or crashes.

Every debugger-enabled process runs an extra thread for handling JDWP protocol packets. This thread is started only for apps that have the `android:debuggable="true"` attribute in the [`Application` element](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") within the Android Manifest.

### Debugging Symbols

Generally, you should provide compiled code with as little explanation as possible. Some metadata, such as debugging information, line numbers, and descriptive function or method names, make the binary or bytecode easier for the reverse engineer to understand, but these aren't needed in a release build and can therefore be safely omitted without impacting the app's functionality.

To inspect native binaries, use a standard tool like `nm` or `objdump` to examine the symbol table. A release build should generally not contain any debugging symbols. If the goal is to obfuscate the library, removing unnecessary dynamic symbols is also recommended.

### Debugging Code and Error Logging

#### StrictMode

StrictMode is a developer tool for detecting violations, e.g. accidental disk or network access on the application's main thread. It can also be used to check for good coding practices, such as implementing performant code.

Here is [an example of `StrictMode`](https://developer.android.com/reference/android/os/StrictMode.html "StrictMode Class") with policies enabled for disk and network access to the main thread:

```java
public void onCreate() {
     if (DEVELOPER_MODE) {
         StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                 .detectDiskReads()
                 .detectDiskWrites()
                 .detectNetwork()   // or .detectAll() for all detectable problems
                 .penaltyLog()
                 .build());
         StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder()
                 .detectLeakedSqlLiteObjects()
                 .detectLeakedClosableObjects()
                 .penaltyLog()
                 .penaltyDeath()
                 .build());
     }
     super.onCreate();
 }
```

Inserting the policy in the `if` statement with the `DEVELOPER_MODE` condition is recommended. To disable `StrictMode`, `DEVELOPER_MODE` must be disabled for the release build.

### Exception Handling

Exceptions occur when an application gets into an abnormal or error state. Both Java and C++ may throw exceptions. Testing exception handling is about ensuring that the app will handle an exception and transition to a safe state without exposing sensitive information via the UI or the app's logging mechanisms.
