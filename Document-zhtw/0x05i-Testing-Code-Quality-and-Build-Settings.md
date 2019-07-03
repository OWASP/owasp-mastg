## Code Quality and Build Settings of Android Apps

### Making Sure That the App is Properly Signed

#### Overview

Android requires all APKs to be digitally signed with a certificate before they are installed or run. The digital signature is used to verify the owner's identity for application updates. This process can prevent an app from being tampered with or modified to include malicious code.

When an APK is signed, a public-key certificate is attached to it. This certificate uniquely associates the APK with the developer and the developer's private key. When an app is being built in debug mode, the Android SDK signs the app with a debug key created specifically for debugging purposes. An app signed with a debug key is not meant to be distributed and won't be accepted in most app stores, including the Google Play Store.

The [final release build](https://developer.android.com/studio/publish/app-signing.html "Android Application Signing") of an app must be signed with a valid release key. In Android Studio, the app can be signed manually or via creation of a signing configuration that's assigned to the release build type.

Prior Android Pie all app updates on Android need to be signed with the same certificate, so a [validity period of 25 years or more is recommended](https://developer.android.com/studio/publish/app-signing#considerations "Android Signing Considerations"). Apps published on Google Play must be signed with a key that that has a validity period ending after October 22th, 2033.

Three APK signing schemes are available:

- JAR signing (v1 scheme),
- APK Signature Scheme v2 (v2 scheme),
- APK Signature Scheme v3 (v3 scheme).

The v2 signature, which is supported by Android 7.0 and above, offers improved security and performance compared to v1 scheme.
The V3 signature, which is supported by Android 9.0 and above, gives apps the ability to change  their signing keys as part of an APK update. This functionality assures compatibility and apps continuous availibility by allowing both the new and the old keys to be used.

For each signing scheme the release builds should always be signed via all its previous schemes as well.

#### Static Analysis

Make sure that the release build has been signed via both the v1 and v2 schemes for Android 7 and above and via all the three schemes for android 9 and above, and that the code-signing certificate in the APK belongs to the developer.

APK signatures can be verified with the `apksigner` tool. It is located at `[SDK-Path]/build-tools/[version]`.

```shell
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
```

The contents of the signing certificate can be examined with `jarsigner`. Note that the Common Name (CN) attribute is set to "Android Debug" in the debug certificate.

The output for an APK signed with a debug certificate is shown below:

```shell

$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path doesn\'t chain with any of the trust anchors]
(...)

```

Ignore the "CertPath not validated" error. This error occurs with Java SDK 7 and above. Instead of `jarsigner`, you can rely on the `apksigner` to verify the certificate chain.

The signing configuration can be managed through Android Studio or the `signingConfig` block in `build.gradle`. To activate both the v1 and v2 and v3 schemes, the following values must be set:

```groovy
v1SigningEnabled true
v2SigningEnabled true
v3SigningEnabled true
```

Several best practices for [configuring the app for release](https://developer.android.com/tools/publishing/preparing.html#publishing-configure "Best Practices for configuring an Android App for Release") are available in the official Android developer documentation.

#### Dynamic Analysis

Static analysis should be used to verify the APK signature.

### Determining Whether the App is Debuggable

#### Overview

The `android:debuggable` attribute in the [`Application`  element](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") that is defined in the Android manifest determines whether the app can be debugged or not.

#### Static Analysis

Check `AndroidManifest.xml` to determine whether the `android:debuggable` attribute has been set and to find the attribute's value:

```xml
    ...
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    ...
```

For a release build, this attribute should always be set to "false" (the default value).

#### Dynamic Analysis

Drozer can be used to determine whether an application is debuggable. The Drozer module `app.package.attacksurface` also displays information about IPC components exported by the application.

```shell
dz> run app.package.attacksurface com.mwr.dz
Attack Surface:
  1 activities exported
  1 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

To scan for all debuggable applications on a device, use the `app.package.debuggable` module:

```shell
dz> run app.package.debuggable
Package: com.mwr.dz
  UID: 10083
  Permissions:
   - android.permission.INTERNET
Package: com.vulnerable.app
  UID: 10084
  Permissions:
   - android.permission.INTERNET
```

If an application is debuggable, executing application commands is trivial. In the `adb` shell, execute `run-as` by appending the package name and application command to the binary name:

```shell
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](https://developer.android.com/tools/debugging/debugging-studio.html "Debugging with Android Studio") can also be used to debug an application and verify debugging activation for an app.

Another method for determining whether an application is debuggable is attaching `jdb` to the running process. If this is successful, debugging will be activated.

The following procedure can be used to start a debug session with `jdb`:

1. Using `adb` and `jdwp`, identify the PID of the active application that you want to debug:

    ```shell
    $ adb jdwp
    2355
    16346  <== last launched, corresponds to our application
    ```

2. Create a communication channel by using `adb` between the application process (with the PID) and the analysis workstation by using a specific local port:

    ```shell
    # adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
    $ adb forward tcp:55555 jdwp:16346
    ```

3. Using `jdb`, attach the debugger to the local communication channel port and start a debug session:

    ```shell
    $ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
    Set uncaught java.lang.Throwable
    Set deferred uncaught java.lang.Throwable
    Initializing jdb ...
    > help
    ```

A few notes about debugging:

- The tool [`JADX`](https://github.com/skylot/jadx "JADX") can be used to identify interesting locations for breakpoint insertion.
- Help with `jdb` is available [here](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm "JDB basic commands").
- If a "the connection to the debugger has been closed" error occurs while `jdb` is being binded to the local communication channel port, kill all `adb` sessions and start a single new session.

### Finding Debugging Symbols

#### Overview

Generally, you should provide compiled code with as little explanation as possible. Some metadata, such as debugging information, line numbers, and descriptive function or method names, make the binary or byte-code easier for the reverse engineer to understand, but these aren't needed in a release build and can therefore be safely omitted without impacting the app's functionality.

To inspect native binaries, use a standard tool like `nm` or `objdump` to examine the symbol table. A release build should generally not contain any debugging symbols. If the goal is to obfuscate the library, removing unnecessary dynamic symbols is also recommended.

#### Static Analysis

Symbols are usually stripped during the build process, so you need the compiled byte-code and libraries to make sure that unnecessary metadata has been discarded.

First, find the `nm` binary in your Android NDK and export it (or create an alias).

```shell
export $NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

To display debug symbols:

```shell
$ $NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

To display dynamic symbols:

```shell
$ $NM -D libfoo.so
```

Alternatively, open the file in your favorite disassembler and check the symbol tables manually.

Dynamic symbols can be stripped via the `visibility` compiler flag. Adding this flag causes gcc to discard the function names while preserving the names of functions declared as `JNIEXPORT`.

Make sure that the following has been added to build.gradle:

```groovy
externalNativeBuild {
    cmake {
        cppFlags "-fvisibility=hidden"
    }
}
```

#### Dynamic Analysis

Static analysis should be used to verify debugging symbols.

### Finding Debugging Code and Verbose Error Logging

#### Overview

StrictMode is a developer tool for detecting violations, e.g. accidental disk or network access on the application's main thread. It can also be used to check for good coding practices, such as implementing performant code.

Here is [an example of `StrictMode`](https://developer.android.com/reference/android/os/StrictMode.html "StrictMode Class") with policies enabled for disk and network access to the main thread:

```Java
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

#### Static Analysis

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

#### Dynamic Analysis

There are several ways of detecting `StrictMode`; the best choice depends on how the policies' roles are implemented. They include

- Logcat,
- a warning dialog,
- application crash.

### Testing for Injection Flaws

#### Overview

Android apps can expose functionality through custom URL schemes (which are a part of Intents). They can expose functionality to

- other apps (via IPC mechanisms, such as Intents, Binders, Android Shared Memory (ASHMEM), or BroadcastReceivers),
- the user (via the user interface).

None of the input from these sources can be trusted; it must be validated and/or sanitized. Validation ensures processing of data that the app is expecting only. If validation is not enforced, any input can be sent to the app, which may allow an attacker or malicious app to exploit app functionality.

The following portions of the source code should be checked if any app functionality has been exposed:

- Custom URL schemes. Check the test case "Testing Custom URL Schemes" as well for further test scenarios.
- IPC Mechanisms (Intents, Binders, Android Shared Memory, or BroadcastReceivers). Check the test case "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms" as well for further test scenarios.
- User interface

An example of a vulnerable IPC mechanism is shown below.

You can use *ContentProviders* to access database information, and you can probe services to see if they return data. If data is not validated properly, the content provider may be prone to SQL injection while other apps are interacting with it. See the following vulnerable implementation of a *ContentProvider*.

```xml
<provider
    android:name=".OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation"
    android:authorities="sg.vp.owasp_mobile.provider.College">
</provider>
```

The `AndroidManifest.xml` above defines a content provider that's exported and therefore available to all other apps. The `query` function in the `OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.java` class should be inspected.

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,String[] selectionArgs, String sortOrder) {
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables(STUDENTS_TABLE_NAME);

    switch (uriMatcher.match(uri)) {
        case STUDENTS:
            qb.setProjectionMap(STUDENTS_PROJECTION_MAP);
            break;

        case STUDENT_ID:
            // SQL Injection when providing an ID
            qb.appendWhere( _ID + "=" + uri.getPathSegments().get(1));
            Log.e("appendWhere",uri.getPathSegments().get(1).toString());
            break;

        default:
            throw new IllegalArgumentException("Unknown URI " + uri);
    }

    if (sortOrder == null || sortOrder == ""){
        /**
         * By default sort on student names
         */
        sortOrder = NAME;
    }
    Cursor c = qb.query(db, projection, selection, selectionArgs,null, null, sortOrder);

    /**
     * register to watch a content URI for changes
     */
    c.setNotificationUri(getContext().getContentResolver(), uri);
    return c;
}
```

While the user is providing a STUDENT_ID at `content://sg.vp.owasp_mobile.provider.College/students`, the query statement is prone to SQL injection. Obviously [prepared statements](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet "OWASP SQL Injection Cheat Sheet") must be used to avoid SQL injection, but [input validation](https://www.owasp.org/index.php/Input_Validation_Cheat_Sheet "OWASP Input Validation Cheat Sheet") should also be applied so that only input that the app is expecting is processed.

All app functions that process data coming in through the UI should implement input validation:

- For user interface input, [Android Saripaar v2](https://github.com/ragunathjawahar/android-saripaar "Android Saripaar v2") can be used.
- For input from IPC or URL schemes, a validation function should be created. For example, the following determines whether the [string is alphanumeric](https://stackoverflow.com/questions/11241690/regex-for-checking-if-a-string-is-strictly-alphanumeric "Input Validation"):

```java
public boolean isAlphaNumeric(String s){
    String pattern= "^[a-zA-Z0-9]*$";
    return s.matches(pattern);
}
```

An alternative to validation functions is type conversion, with, for example, `Integer.parseInt` if only integers are expected. The [OWASP Input Validation Cheat Sheet](https://www.owasp.org/index.php/Input_Validation_Cheat_Sheet "OWASP Input Validation Cheat Sheet") contains more information about this topic.

#### Dynamic Analysis

The tester should manually test the input fields with strings like `OR 1=1--` if, for example, a local SQL injection vulnerability has been identified.

On a rooted device, the command content can be used to query the data from a Content Provider. The following command queries the vulnerable function described above.

```shell
# content query --uri content://sg.vp.owasp_mobile.provider.College/students
```

SQL injection can be exploited with the following command. Instead of getting the record for Bob only, the user can retrieve all data.

```shell
# content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''"
```

Drozer can also be used for dynamic testing.

### Testing Exception Handling

#### Overview

Exceptions occur when an application gets into an abnormal or error state. Both Java and C++ may throw exceptions. Testing exception handling is about ensuring that the app will handle an exception and transition to a safe state without exposing sensitive information via the UI or the app's logging mechanisms.

#### Static Analysis

Review the source code to understand the application and identify how it handles different types of errors (IPC communications, remote services invocation, etc.). Here are some examples of things to check at this stage:

- Make sure that the application uses a well-designed and unified scheme to [handle exceptions](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047 "Exceptional Behavior (ERR)").
- Plan for standard `RuntimeException`s (e.g.`NullPointerException`, `IndexOutOfBoundsException`, `ActivityNotFoundException`, `CancellationException`, `SQLException`) by creating proper null checks, bound checks, and the like. An [overview of the available subclasses of `RuntimeException`](https://developer.android.com/reference/java/lang/RuntimeException.html "Runtime Exception Class") can be found in the Android developer documentation. A child of `RuntimeException` should be thrown intentionally, and the intent should be handled by the calling method.
- Make sure that for every non-runtime `Throwable` there's a proper catch handler, which ends up handling the actual exception properly.
- When an exception is thrown, make sure that the application has centralized handlers for exceptions that cause similar behavior. This can be a static class. For exceptions specific to the method, provide specific catch blocks.
- Make sure that the application doesn't expose sensitive information while handling exceptions in its UI or log-statements. Ensure that exceptions are still verbose enough to explain the issue to the user.
- Make sure that all confidential information handled by high-risk applications is always wiped during execution of the `finally` blocks.

```java
byte[] secret;
try{
    //use secret
} catch (SPECIFICEXCEPTIONCLASS | SPECIFICEXCEPTIONCLASS2  e) {
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

#### Dynamic Analysis

There are several ways to do dynamic analysis:

- Use Xposed to hook into methods and either call them with unexpected values or overwrite existing variables with unexpected values (e.g., null values).
- Type unexpected values into the Android application's UI fields.
- Interact with the application using its intents, its public providers, and unexpected values.
- Tamper with the network communication and/or the files stored by the application.

The application should never crash; it should

- recover from the error or transition into a state in which it can inform the user of its inability to continue,
- if necessary, tell the user to take appropriate action (The message should not leak sensitive information.),
- not provide any information in logging mechanisms used by the application.

### Make Sure That Free Security Features Are Activated

#### Overview

Because decompiling Java classes is trivial, applying some basic obfuscation to the release byte-code is recommended. ProGuard offers an easy way to shrink and obfuscate code and to strip unneeded debugging information from the byte-code of Android Java apps. It replaces identifiers, such as class names, method names, and variable names, with meaningless character strings. This is a type of layout obfuscation, which is "free" in that it doesn't impact the program's performance.

Since most Android applications are Java-based, they are [immune to buffer overflow vulnerabilities](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java "Java Buffer Overflows"). Nevertheless, a buffer overflow vulnerability may still be applicable when you're using the Android NDK; therefore, consider secure compiler settings.

#### Static Analysis

If source code is provided, you can check the build.gradle file to see whether obfuscation settings have been applied. In the example below, you can see that `minifyEnabled` and `proguardFiles` are set. Creating exceptions to protect some classes from obfuscation (with "-keepclassmembers" and "-keep class") is common. Therefore, auditing the ProGuard configuration file to see what classes are exempted is important. The `getDefaultProguardFile('proguard-android.txt')` method gets the default ProGuard settings from the `<Android SDK>/tools/proguard/` folder. The file `proguard-rules.pro` is where you define custom ProGuard rules. You can see that many extended classes in our sample `proguard-rules.pro` file are common Android classes. This should be defined more granularly on specific classes or libraries.

By default, ProGuard removes attributes that are useful for debugging, including line numbers, source file names, and variable names. ProGuard is a free Java class file shrinker, optimizer, obfuscator, and pre-verifier. It is shipped with Android's SDK tools. To activate shrinking for the release build, add the following to build.gradle:

```groovy
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

proguard-rules.pro

```groovy
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
```

#### Dynamic Analysis

If source code has not been provided, an APK can be decompiled to determine whether the codebase has been obfuscated. Several tools are available for converting dex code to a jar file (e.g., dex2jar). The jar file can be opened with tools (such as JD-GUI) that can be used to make sure that class, method, and variable names are not human-readable.

Sample obfuscated code block:

```java
package com.a.a.a;

import com.a.a.b.a;
import java.util.List;

class a$b
  extends a
{
  public a$b(List paramList)
  {
    super(paramList);
  }

  public boolean areAllItemsEnabled()
  {
    return true;
  }

  public boolean isEnabled(int paramInt)
  {
    return true;
  }
}
```

### Memory Corruption Bugs

Android applications often run on a VM where most of the memory corruption issues have been taken care off.
This does not mean that there are no memory corruption bugs. Take [CVE-2018-9522](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9522 "CVE in StatsLogEventWrapper") for instance, which is related to serialization issues using Parcels. Next, in native code, we still see the same issues as we explained in the general memory corruption section. Last, we see memory bugs in supporting services, such as with the stagefreight attack as shown [at BlackHat](https://www.blackhat.com/docs/us-15/materials/us-15-Drake-Stagefright-Scary-Code-In-The-Heart-Of-Android.pdf "Stagefreight").

A memory leak is often an issue as well. This can happen for instance when a reference to the `Context` object is passed around to non-`Activity` classes, or when you pass references to `Activity` classes to your helperclasses.

#### Static Analysis

There are various items to look for:

- Are there native code parts? If so: check for the given issues in the general memory corruption section. Native code can easily be spotted given JNI-wrappers, .CPP/.H/.C files, NDK or other native frameworks.
- Is there Java code or Kotlin code? Look for Serialization/deserialization issues, such as described in [A brief history of Android deserialization vulnerabilities](https://lgtm.com/blog/android_deserialization "android deserialization").

Note that there can be Memory leaks in Java/Kottline code as well. Look for various items, such as: BroadcastReceivers which are not unregistered, static references to `Activity` or `View` classes, Singleton classes that have references to `Context`, Inner Class references, Anonymous Class references, AsyncTask references, Handler references, Threading done wrong, TimerTask references. For more details, please check:

- [9 ways to avoid memory leaks in Android](https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e "9 ways to avoid memory leaks in Android")
- [Memory Leak Patterns in Android](https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570 "Memory Leak Patterns in Android").

#### Dynamic Analysis

There are various steps to take:

- In case of native code: use Valgrind or Mempatrol to analyse the memory usage and memory calls made by the code.
- In case of Java/Kotlin code, try to recompile the app and use it with [Squares leak canary](https://github.com/square/leakcanary "Leakcanary").
- Check with the [Memory Profiler from Android Studio](https://developer.android.com/studio/profile/memory-profiler "Memory profiler") for leakage.
- Check with the [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda "Android Java Deserialization Vulnerability Tester"), for serialization vulnerabilities.

### Checking for Weaknesses in Third Party Libraries

#### Overview

Android apps often make use of third party libraries. These third party libraries accelerate development as the developer has to write less code in order to solve a problem. There are two categories of libraries:

- Libraries that are not (or should not) be packed within the actual production application, such as `Mockito` used for testing and libraries like `JavaAssist` used to compile certain other libraries.
- Libraries that are packed within the actual production application, such as `Okhttp3`.

These libraries can have the following two classes of unwanted side-effects:

- A library can contain a vulnerability, which will make the application vulnerable. A good example are the versions of `OKHTTP` prior to 2.7.5 in which TLS chain pollution was possible to bypass SSL pinning.
- A library can use a license, such as LGPL2.1, which requires the application author to provide access to the source code for those who use the application and request insight in its sources. In fact the application should then be allowed to be redistributed with modifications to its sourcecode. This can endanger the intellectual property (IP) of the application.

Please note that this issue can hold on multiple levels: When you use webviews with JavaScript running in the webview, the JavaScript libraries can have these issues as well. The same holds for plugins/libraries for Cordova, React-native and Xamarin apps.

#### Static Analysis

##### Detecting vulnerabilities of third party libraries

Detecting vulnerabilities in third party dependencies can be done by means of the OWASP Dependency checker. This is best done by using a gradle plugin, such as `dependency-check-gradle`.
In order to use the plugin, the following steps need to be applied:
Install the plugin from the Maven central repository by adding the following script to your build.gradle:

```groovy
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

```shell
$ gradle assemble
$ gradle dependencyCheckAnalyze --info
```

The report will be in `build/reports` unless otherwise configured. Use the report in order to analyze the vulnerabilities found. See remediation on what to do given the vulnerabilities found with the libraries.

Please be advised that the plugin requires to download a vulnerability feed. Consult the documentation in case issues arise with the plugin.

Alternatively there are commercial tools which might have a better coverage of the dependencies found for the libraries being used, such as SourceClear or Blackduck. The actual result of using either the OWASP Dependency Checker or another tool varies on the type of (NDK related or SDK related) libraries.

Lastly, please note that for hybrid applications, one will have to check the JavaScript dependencies with RetireJS. Similarly for Xamarin, one will have to check the C# dependencies.

When a library is found to contain vulnerabilities, then the following reasoning applies:

- Is the library packaged with the application? Then check whether the library has a version in which the vulnerability is patched. If not, check whether the vulnerability actually affects the application. If that is the case or might be the case in the future, then look for an alternative which provides similar functionality, but without the vulnerabilities.
- Is the library not packaged with the application? See if there is a patched version in which the vulnerability is fixed. If this is not the case, check if the  implications of the vulnerability for the build-process. Could the vulnerability impede a build or weaken the security of the build-pipeline? Then try looking for an alternative in which the vulnerability is fixed.

When the sources are not available, one can decompile the app and check the jar files. When Dexguard or Proguard are applied properly, then version information about the library is often obfuscated and therefore gone. Otherwise you can still find the information very often in the comments of the Java files of given libraries. Tools such as MobSF can help in analyzing the possible libraries packed with the application. If you can retrieve the version of the library, either via comments, or via specific methods used in certain versions, you can look them up for CVEs by hand.

##### Detecting the licenses used by the libraries of the application

In order to ensure that the copyright laws are not infringed, one can best check the dependencies by using a plugin which can iterate over the different libraries, such as `License Gradle Plugin`. This plugin can be used by taking the following steps.

In your `build.gradle` file add:

```groovy
plugins {
    id "com.github.hierynomus.license-report" version"{license_plugin_version}"
}
```

Now, after the plugin is picked up, use the following commands:

```shell
$ gradle assemble
$ gradle downloadLicenses
```

Now a license-report will be generated, which can be used to consult the licenses used by the third party libraries. Please check the license agreements to see whether a copyright notice needs to be included into the app and whether the license type requires to open-source the code of the application.

Similar to dependency checking, there are commercial tools which are able to check the licenses as well, such as SourceClear, Snyk or Blackduck.

> Note: If in doubt about the implications of a license model used by a third party library, then consult with a legal specialist.

When a library contains a license in which the application IP needs to be open-sourced, check if there is an alternative for the library which can be used to provide similar functionalities.

Note: In case of a hybrid app, please check the build tools used: most of them do have a license enumeration plugin to find the licenses being used.

When the sources are not available, one can decompile the app and check the jar files. When Dexguard or Proguard are applied properly, then version information about the library is often gone. Otherwise you can still find it very often in the comments of the Java files of given libraries. Tools such as MobSF can help in analyzing the possible libraries packed with the application. If you can retrieve the version of the library, either via comments, or via specific methods used in certain versions, you can look them up for their licenses being used by hand.

#### Dynamic Analysis

The dynamic analysis of this section comprises validating whether the copyrights of the licenses have been adhered to. This often means that the application should have an `about` or `EULA` section in which the copy-right statements are noted as required by the license of the third party library.

### References

#### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality>

#### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."
- V7.1: "The app is signed and provisioned with valid certificate."
- V7.2: "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable)."
- V7.3: "Debugging symbols have been removed from native binaries."
- V7.4: "Debugging code has been removed, and the app does not log verbose errors or debugging messages."
- V7.5: "All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities."
- V7.6: "The app catches and handles possible exceptions."
- V7.7: "Error handling logic in security controls denies access by default."
- V7.8: "In unmanaged code, memory is allocated, freed and used securely."
- V7.9: "Free security features offered by the toolchain, such as byte-code minification, stack protection, PIE support and automatic reference counting, are activated."

#### CWE

- CWE-20 - Improper Input Validation
- CWE-215 - Information Exposure through Debug Information
- CWE-388 - Error Handling
- CWE-489 - Leftover Debug Code
- CWE-656 - Reliance on Security through Obscurity
- CWE-937 - OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

#### Tools

- ProGuard - <https://www.guardsquare.com/en/proguard>
- jarsigner - <http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html>
- Xposed - <http://repo.xposed.info/>
- Drozer - <https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf>
- GNU nm - <https://ftp.gnu.org/old-gnu/Manuals/binutils-2.12/html_node/binutils_4.html>
- Black Duck - <https://www.blackducksoftware.com/>
- Sourceclear -  <https://www.sourceclear.com/>
- Snyk - <https://snyk.io/>
- Gradle license plugn - <https://github.com/hierynomus/license-gradle-plugin>
- Dependency-check-gradle - <https://github.com/jeremylong/dependency-check-gradle>
- MobSF - <https://www.github.com/MobSF/Mobile-Security-Framework-MobSF>
- Squares leak canary - <https://github.com/square/leakcanary>
- Memory Profiler from Android Studio - <https://developer.android.com/studio/profile/memory-profiler>
- Android Java Deserialization Vulnerability Tester - <https://github.com/modzero/modjoda>

#### Memory Analysis References

- A brief history of Android deserialization vulnerabilities - <https://lgtm.com/blog/android_deserialization>
- 9 ways to avoid memory leaks in Android - <https://android.jlelse.eu/9-ways-to-avoid-memory-leaks-in-android-b6d81648e35e>
- Memory Leak Patterns in Android - <https://android.jlelse.eu/memory-leak-patterns-in-android-4741a7fcb570>

#### Android Documentation

- APK signature scheme with key rotation - <https://developer.android.com/about/versions/pie/android-9.0#apk-key-rotation>
