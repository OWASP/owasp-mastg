# Android Code Quality and Build Settings

## Overview

## Making Sure That the App is Properly Signed (MSTG-CODE-1)

### Overview

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

### Static Analysis

Make sure that the release build has been signed via both the v1 and v2 schemes for Android 7.0 (API level 24) and above and via all the three schemes for Android 9 (API level 28) and above, and that the code-signing certificate in the APK belongs to the developer.

APK signatures can be verified with the `apksigner` tool. It is located at `[SDK-Path]/build-tools/[version]`.

```bash
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

The contents of the signing certificate can be examined with `jarsigner`. Note that the Common Name (CN) attribute is set to "Android Debug" in the debug certificate.

The output for an APK signed with a debug certificate is shown below:

```bash

$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path doesn\'t chain with any of the trust anchors]
(...)

```

Ignore the "CertPath not validated" error. This error occurs with Java SDK 7 and above. Instead of `jarsigner`, you can rely on the `apksigner` to verify the certificate chain.

The signing configuration can be managed through Android Studio or the `signingConfig` block in `build.gradle`. To activate both the v1 and v2 schemes, the following values must be set:

```default
v1SigningEnabled true
v2SigningEnabled true
```

Several best practices for [configuring the app for release](https://developer.android.com/tools/publishing/preparing.html#publishing-configure "Best Practices for configuring an Android App for Release") are available in the official Android developer documentation.

Last but not least: make sure that the application is never deployed with your internal testing certificates.

### Dynamic Analysis

Static analysis should be used to verify the APK signature.

## Testing Whether the App is Debuggable (MSTG-CODE-2)

### Overview

The `android:debuggable` attribute in the [`Application` element](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") that is defined in the Android manifest determines whether the app can be debugged or not.

### Static Analysis

Check `AndroidManifest.xml` to determine whether the `android:debuggable` attribute has been set and to find the attribute's value:

```xml
    ...
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    ...
```

You can use `aapt` tool from the Android SDK with the following command line to quickly check if the `android:debuggable="true"` directive is present:

```bash
# If the command print 1 then the directive is present
# The regex search for this line: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
$ aapt d xmltree sieve.apk AndroidManifest.xml | grep -Ec "android:debuggable\(0x[0-9a-f]+\)=\(type\s0x[0-9a-f]+\)0xffffffff"
1
```

For a release build, this attribute should always be set to `"false"` (the default value).

### Dynamic Analysis

`adb` can be used to determine whether an application is debuggable.

Use the following command:

```bash
# If the command print a number superior to zero then the application have the debug flag
# The regex search for these lines:
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
# pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
$ adb shell dumpsys package com.mwr.example.sieve | grep -c "DEBUGGABLE"
2
$ adb shell dumpsys package com.nondebuggableapp | grep -c "DEBUGGABLE"
0
```

If an application is debuggable, executing application commands is trivial. In the `adb` shell, execute `run-as` by appending the package name and application command to the binary name:

```bash
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](https://developer.android.com/tools/debugging/debugging-studio.html "Debugging with Android Studio") can also be used to debug an application and verify debugging activation for an app.

Another method for determining whether an application is debuggable is attaching `jdb` to the running process. If this is successful, debugging will be activated.

The following procedure can be used to start a debug session with `jdb`:

1. Using `adb` and `jdwp`, identify the PID of the active application that you want to debug:

    ```bash
    $ adb jdwp
    2355
    16346  <== last launched, corresponds to our application
    ```

2. Create a communication channel by using `adb` between the application process (with the PID) and your host computer by using a specific local port:

    ```bash
    # adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
    $ adb forward tcp:55555 jdwp:16346
    ```

3. Using `jdb`, attach the debugger to the local communication channel port and start a debug session:

    ```bash
    $ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
    Set uncaught java.lang.Throwable
    Set deferred uncaught java.lang.Throwable
    Initializing jdb ...
    > help
    ```

A few notes about debugging:

- The tool [`JADX`](https://github.com/skylot/jadx "JADX") can be used to identify interesting locations for breakpoint insertion.
- Usage of basic commands for jdb can be found at [Tutorialspoint](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm "jdb basic commands").
- If you get an error telling that "the connection to the debugger has been closed" while `jdb` is being bound to the local communication channel port, kill all adb sessions and start a single new session.

## Testing for Debugging Symbols (MSTG-CODE-3)

### Overview

Generally, you should provide compiled code with as little explanation as possible. Some metadata, such as debugging information, line numbers, and descriptive function or method names, make the binary or bytecode easier for the reverse engineer to understand, but these aren't needed in a release build and can therefore be safely omitted without impacting the app's functionality.

To inspect native binaries, use a standard tool like `nm` or `objdump` to examine the symbol table. A release build should generally not contain any debugging symbols. If the goal is to obfuscate the library, removing unnecessary dynamic symbols is also recommended.

### Static Analysis

Symbols are usually stripped during the build process, so you need the compiled bytecode and libraries to make sure that unnecessary metadata has been discarded.

First, find the `nm` binary in your Android NDK and export it (or create an alias).

```bash
export NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

To display debug symbols:

```bash
$NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

To display dynamic symbols:

```bash
$NM -D libfoo.so
```

Alternatively, open the file in your favorite disassembler and check the symbol tables manually.

Dynamic symbols can be stripped via the `visibility` compiler flag. Adding this flag causes gcc to discard the function names while preserving the names of functions declared as `JNIEXPORT`.

Make sure that the following has been added to build.gradle:

```default
externalNativeBuild {
    cmake {
        cppFlags "-fvisibility=hidden"
    }
}
```

### Dynamic Analysis

Static analysis should be used to verify debugging symbols.

## Testing for Debugging Code and Verbose Error Logging (MSTG-CODE-4)

### Overview

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

### Static Analysis

To determine whether `StrictMode` is enabled, you can look for the `StrictMode.setThreadPolicy` or `StrictMode.setVmPolicy` methods. Most likely, they will be in the `onCreate` method.

The [detection methods for the thread policy](https://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") are

```java
detectDiskWrites()
detectDiskReads()
detectNetwork()
```

The [penalties for thread policy violation](https://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") are

```java
penaltyLog() // Logs a message to LogCat
penaltyDeath() // Crashes application, runs at the end of all enabled penalties
penaltyDialog() // Shows a dialog
```

Have a look at the [best practices](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581 "Android Best Practices: StrictMode") for using StrictMode.

### Dynamic Analysis

There are several ways of detecting `StrictMode`; the best choice depends on how the policies' roles are implemented. They include

- Logcat,
- a warning dialog,
- application crash.

## Checking for Weaknesses in Third Party Libraries (MSTG-CODE-5)

### Overview

Android apps often make use of third party libraries. These third party libraries accelerate development as the developer has to write less code in order to solve a problem. There are two categories of libraries:

- Libraries that are not (or should not) be packed within the actual production application, such as `Mockito` used for testing and libraries like `JavaAssist` used to compile certain other libraries.
- Libraries that are packed within the actual production application, such as `Okhttp3`.

These libraries can lead to unwanted side-effects:

- A library can contain a vulnerability, which will make the application vulnerable. A good example are the versions of `OKHTTP` prior to 2.7.5 in which TLS chain pollution was possible to bypass SSL pinning.
- A library can no longer be maintained or hardly be used, which is why no vulnerabilities are reported and/or fixed. This can lead to having bad and/or vulnerable code in your application through the library.
- A library can use a license, such as LGPL2.1, which requires the application author to provide access to the source code for those who use the application and request insight in its sources. In fact the application should then be allowed to be redistributed with modifications to its sourcecode. This can endanger the intellectual property (IP) of the application.

Please note that this issue can hold on multiple levels: When you use webviews with JavaScript running in the webview, the JavaScript libraries can have these issues as well. The same holds for plugins/libraries for Cordova, React-native and Xamarin apps.

### Static Analysis

#### Detecting vulnerabilities of third party libraries

Detecting vulnerabilities in third party dependencies can be done by means of the OWASP Dependency checker. This is best done by using a gradle plugin, such as [`dependency-check-gradle`](https://github.com/jeremylong/dependency-check-gradle "dependency-check-gradle").
In order to use the plugin, the following steps need to be applied:
Install the plugin from the Maven central repository by adding the following script to your build.gradle:

```default
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:3.2.0'
    }
}

apply plugin: 'org.owasp.dependencycheck'
```

Once gradle has invoked the plugin, you can create a report by running:

```bash
gradle assemble
gradle dependencyCheckAnalyze --info
```

The report will be in `build/reports` unless otherwise configured. Use the report in order to analyze the vulnerabilities found. See remediation on what to do given the vulnerabilities found with the libraries.

Please be advised that the plugin requires to download a vulnerability feed. Consult the documentation in case issues arise with the plugin.

Alternatively there are commercial tools which might have a better coverage of the dependencies found for the libraries being used, such as [Sonatype Nexus IQ](https://www.sonatype.com/nexus/iqserver "Nexus IQ"), [Sourceclear](https://www.sourceclear.com/ "Sourceclear"), [Snyk](https://snyk.io/ "Snyk") or [Blackduck](https://www.blackducksoftware.com/ "Blackduck"). The actual result of using either the OWASP Dependency Checker or another tool varies on the type of (NDK related or SDK related) libraries.

Lastly, please note that for hybrid applications, one will have to check the JavaScript dependencies with RetireJS. Similarly for Xamarin, one will have to check the C# dependencies.

When a library is found to contain vulnerabilities, then the following reasoning applies:

- Is the library packaged with the application? Then check whether the library has a version in which the vulnerability is patched. If not, check whether the vulnerability actually affects the application. If that is the case or might be the case in the future, then look for an alternative which provides similar functionality, but without the vulnerabilities.
- Is the library not packaged with the application? See if there is a patched version in which the vulnerability is fixed. If this is not the case, check if the implications of the vulnerability for the build-process. Could the vulnerability impede a build or weaken the security of the build-pipeline? Then try looking for an alternative in which the vulnerability is fixed.

When the sources are not available, one can decompile the app and check the JAR files. When Dexguard or [ProGuard](0x08a-Testing-Tools.md#proguard) are applied properly, then version information about the library is often obfuscated and therefore gone. Otherwise you can still find the information very often in the comments of the Java files of given libraries. Tools such as MobSF can help in analyzing the possible libraries packed with the application. If you can retrieve the version of the library, either via comments, or via specific methods used in certain versions, you can look them up for CVEs by hand.

If the application is a high-risk application, you will end up vetting the library manually. In that case, there are specific requirements for native code, which you can find in the chapter "[Testing Code Quality](0x04h-Testing-Code-Quality.md)". Next to that, it is good to vet whether all best practices for software engineering are applied.

#### Detecting the Licenses Used by the Libraries of the Application

In order to ensure that the copyright laws are not infringed, one can best check the dependencies by using a plugin which can iterate over the different libraries, such as `License Gradle Plugin`. This plugin can be used by taking the following steps.

In your `build.gradle` file add:

```default
plugins {
    id "com.github.hierynomus.license-report" version"{license_plugin_version}"
}
```

Now, after the plugin is picked up, use the following commands:

```bash
gradle assemble
gradle downloadLicenses
```

Now a license-report will be generated, which can be used to consult the licenses used by the third party libraries. Please check the license agreements to see whether a copyright notice needs to be included into the app and whether the license type requires to open-source the code of the application.

Similar to dependency checking, there are commercial tools which are able to check the licenses as well, such as [Sonatype Nexus IQ](https://www.sonatype.com/nexus/iqserver "Nexus IQ"), [Sourceclear](https://www.sourceclear.com/ "Sourceclear"), [Snyk](https://snyk.io/ "Snyk") or [Blackduck](https://www.blackducksoftware.com/ "Blackduck").

> Note: If in doubt about the implications of a license model used by a third party library, then consult with a legal specialist.

When a library contains a license in which the application IP needs to be open-sourced, check if there is an alternative for the library which can be used to provide similar functionalities.

Note: In case of a hybrid app, please check the build tools used: most of them do have a license enumeration plugin to find the licenses being used.

When the sources are not available, one can decompile the app and check the JAR files. When Dexguard or [ProGuard](0x08a-Testing-Tools.md#proguard) are applied properly, then version information about the library is often gone. Otherwise you can still find it very often in the comments of the Java files of given libraries. Tools such as MobSF can help in analyzing the possible libraries packed with the application. If you can retrieve the version of the library, either via comments, or via specific methods used in certain versions, you can look them up for their licenses being used by hand.

### Dynamic Analysis

The dynamic analysis of this section comprises validating whether the copyrights of the licenses have been adhered to. This often means that the application should have an `about` or `EULA` section in which the copy-right statements are noted as required by the license of the third party library.

## Testing Exception Handling (MSTG-CODE-6 and MSTG-CODE-7)

### Overview

Exceptions occur when an application gets into an abnormal or error state. Both Java and C++ may throw exceptions. Testing exception handling is about ensuring that the app will handle an exception and transition to a safe state without exposing sensitive information via the UI or the app's logging mechanisms.

### Static Analysis

Review the source code to understand the application and identify how it handles different types of errors (IPC communications, remote services invocation, etc.). Here are some examples of things to check at this stage:

- Make sure that the application uses a well-designed and unified scheme to [handle exceptions](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88487665 "Exceptional Behavior (ERR)").
- Plan for standard `RuntimeException`s (e.g.`NullPointerException`, `IndexOutOfBoundsException`, `ActivityNotFoundException`, `CancellationException`, `SQLException`) by creating proper null checks, bound checks, and the like. An [overview of the available subclasses of `RuntimeException`](https://developer.android.com/reference/java/lang/RuntimeException.html "Runtime Exception Class") can be found in the Android developer documentation. A child of `RuntimeException` should be thrown intentionally, and the intent should be handled by the calling method.
- Make sure that for every non-runtime `Throwable` there's a proper catch handler, which ends up handling the actual exception properly.
- When an exception is thrown, make sure that the application has centralized handlers for exceptions that cause similar behavior. This can be a static class. For exceptions specific to the method, provide specific catch blocks.
- Make sure that the application doesn't expose sensitive information while handling exceptions in its UI or log-statements. Ensure that exceptions are still verbose enough to explain the issue to the user.
- Make sure that all confidential information handled by high-risk applications is always wiped during execution of the `finally` blocks.

```java
byte[] secret;
try{
    //use secret
} catch (SPECIFICEXCEPTIONCLASS | SPECIFICEXCEPTIONCLASS2 e) {
    // handle any issues
} finally {
    //clean the secret.
}
```

Adding a general exception handler for uncaught exceptions is a best practice for resetting the application's state when a crash is imminent:

```java
public class MemoryCleanerOnCrash implements Thread.UncaughtExceptionHandler {

    private static final MemoryCleanerOnCrash S_INSTANCE = new MemoryCleanerOnCrash();
    private final List<Thread.UncaughtExceptionHandler> mHandlers = new ArrayList<>();

    //initialize the handler and set it as the default exception handler
    public static void init() {
        S_INSTANCE.mHandlers.add(Thread.getDefaultUncaughtExceptionHandler());
        Thread.setDefaultUncaughtExceptionHandler(S_INSTANCE);
    }

     //make sure that you can still add exception handlers on top of it (required for ACRA for instance)
    public void subscribeCrashHandler(Thread.UncaughtExceptionHandler handler) {
        mHandlers.add(handler);
    }

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {

            //handle the cleanup here
            //....
            //and then show a message to the user if possible given the context

        for (Thread.UncaughtExceptionHandler handler : mHandlers) {
            handler.uncaughtException(thread, ex);
        }
    }
}
```

Now the handler's initializer must be called in your custom `Application` class (e.g., the class that extends `Application`):

```java
@Override
protected void attachBaseContext(Context base) {
    super.attachBaseContext(base);
    MemoryCleanerOnCrash.init();
}
```

### Dynamic Analysis

There are several ways to do dynamic analysis:

- Use Xposed to hook into methods and either call them with unexpected values or overwrite existing variables with unexpected values (e.g., null values).
- Type unexpected values into the Android application's UI fields.
- Interact with the application using its intents, its public providers, and unexpected values.
- Tamper with the network communication and/or the files stored by the application.

The application should never crash; it should

- recover from the error or transition into a state in which it can inform the user of its inability to continue,
- if necessary, tell the user to take appropriate action (The message should not leak sensitive information.),
- not provide any information in logging mechanisms used by the application.

## Memory Corruption Bugs (MSTG-CODE-8)

Android applications often run on a VM where most of the memory corruption issues have been taken care off.
This does not mean that there are no memory corruption bugs. Take [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") for instance, which is related to serialization issues using Parcels. Next, in native code, we still see the same issues as we explained in the general memory corruption section. Last, we see memory bugs in supporting services, such as with the Stagefright attack as shown [at BlackHat](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefright").

A memory leak is often an issue as well. This can happen for instance when a reference to the `Context` object is passed around to non-`Activity` classes, or when you pass references to `Activity` classes to your helper classes.

### Static Analysis

There are various items to look for:

- Are there native code parts? If so: check for the given issues in the general memory corruption section. Native code can easily be spotted given JNI-wrappers, .CPP/.H/.C files, NDK or other native frameworks.
- Is there Java code or Kotlin code? Look for Serialization/deserialization issues, such as described in [A brief history of Android deserialization vulnerabilities](https://securitylab.github.com/research/android-deserialization-vulnerabilities "android deserialization").

Note that there can be Memory leaks in Java/Kotlin code as well. Look for various items, such as: BroadcastReceivers which are not unregistered, static references to `Activity` or `View` classes, Singleton classes that have references to `Context`, Inner Class references, Anonymous Class references, AsyncTask references, Handler references, Threading done wrong, TimerTask references. For more details, please check:

- [9 ways to avoid memory leaks in Android](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e "9 ways to avoid memory leaks in Android")
- [Memory Leak Patterns in Android](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570 "Memory Leak Patterns in Android").

### Dynamic Analysis

There are various steps to take:

- In case of native code: use Valgrind or Mempatrol to analyze the memory usage and memory calls made by the code.
- In case of Java/Kotlin code, try to recompile the app and use it with [Squares leak canary](https://github.com/square/leakcanary "Leakcanary").
- Check with the [Memory Profiler from Android Studio](https://developer.android.com/studio/profile/memory-profiler "Memory profiler") for leakage.
- Check with the [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda "Android Java Deserialization Vulnerability Tester"), for serialization vulnerabilities.

## Make Sure That Free Security Features Are Activated (MSTG-CODE-9)

### Overview

The tests used to detect the presence of [binary protection mechanisms](0x04h-Testing-Code-Quality.md#binary-protection-mechanisms) heavily depend on the language used for developing the application.

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

### Static Analysis

Test the app native libraries to determine if they have the PIE and stack smashing protections enabled.

You can use [radare2's rabin2](0x08a-Testing-Tools.md#radare2) to get the binary information. We'll use the [UnCrackable App for Android Level 4](0x08b-Reference-Apps.md#android-uncrackable-l4) v1.0 APK as an example.

All native libraries must have `canary` and `pic` both set to `true`.

That's the case for `libnative-lib.so`:

```sh
rabin2 -I lib/x86_64/libnative-lib.so | grep -E "canary|pic"
canary   true
pic      true
```

But not for `libtool-checker.so`:

```sh
rabin2 -I lib/x86_64/libtool-checker.so | grep -E "canary|pic"
canary   false
pic      true
```

In this example, `libtool-checker.so` must be recompiled with stack smashing protection support.

## References

### OWASP MASVS

- MSTG-CODE-1: "The app is signed and provisioned with a valid certificate, of which the private key is properly protected."
- MSTG-CODE-2: "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable)."
- MSTG-CODE-3: "Debugging symbols have been removed from native binaries."
- MSTG-CODE-4: "Debugging code and developer assistance code (e.g. test code, backdoors, hidden settings) have been removed. The app does not log verbose errors or debugging messages."
- MSTG-CODE-5: "All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities."
- MSTG-CODE-6: "The app catches and handles possible exceptions."
- MSTG-CODE-7: "Error handling logic in security controls denies access by default."
- MSTG-CODE-8: "In unmanaged code, memory is allocated, freed and used securely."
- MSTG-CODE-9: "Free security features offered by the toolchain, such as byte-code minification, stack protection, PIE support and automatic reference counting, are activated."

### Memory Analysis References

- A brief history of Android deserialization vulnerabilities - <https://securitylab.github.com/research/android-deserialization-vulnerabilities>
- 9 ways to avoid memory leaks in Android - <https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e>
- Memory Leak Patterns in Android - <https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570>

### Android Documentation

- APK signature scheme with key rotation - <https://developer.android.com/about/versions/pie/android-9.0#apk-key-rotation>
