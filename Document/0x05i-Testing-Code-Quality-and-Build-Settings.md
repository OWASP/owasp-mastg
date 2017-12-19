## Code Quality and Build Settings of Android Apps

### Verifying That the App is Properly Signed

#### Overview

Android requires that all APKs are digitally signed with a certificate before they can be installed. The digital signature is required by the Android system before installing/running an application, and it's also used to verify the identity of the owner for future updates of the application. This process can prevent an app from being tampered with, or modified to include malicious code.

When an APK is signed, a public-key certificate is attached to the APK. This certificate uniquely associates the APK to the developer and their corresponding private key. When building an app in debug mode, the Android SDK signs the app with a debug key specifically created for debugging purposes. An app signed with a debug key is not be meant for distribution and won't be accepted in most app stores, including the Google Play Store. To prepare the app for final release, the app must be signed with a release key belonging to the developer.

The [final release build](https://developer.android.com/studio/publish/app-signing.html "Application Signing")) of an app must be signed with a valid release key. In Android Studio, this can be done manually or by creating a signing configuration and assigning it to the release build type.

Note that Android expects any updates to the app to be signed with the same certificate, so a validity period of 25 years or more is recommended. Apps published on Google Play must be signed with a certificate that is valid at least until October 22th, 2033.

Two APK signing schemes are available:
- JAR signing (v1 scheme) and
- APK Signature Scheme v2 (v2 scheme).

The v2 signature, which is supported by Android 7.0 and higher, offers improved security and performance. Release builds should always be signed using *both* schemes.


#### Static Analysis

Verify that the release build is signed with both v1 and v2 scheme, and that the code signing certificate contained in the APK belongs to the developer.

APK signatures can be verified using the `apksigner` tool.

```bash
$ apksigner verify --verbose Desktop/example.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Number of signers: 1
```

The contents of the signing certificate can be examined using `jarsigner`. Note the in the debug certificate, the Common Name(CN) attribute is set to "Android Debug".

The output for an APK signed with a Debug certificate looks as follows:

```
$ jarsigner -verify -verbose -certs example.apk

sm     11116 Fri Nov 11 12:07:48 ICT 2016 AndroidManifest.xml

      X.509, CN=Android Debug, O=Android, C=US
      [certificate is valid from 3/24/16 9:18 AM to 8/10/43 9:18 AM]
      [CertPath not validated: Path does not chain with any of the trust anchors]
(...)
```

Ignore the "CertPath not validated" error -  this error appears with Java SDK 7 and greater. Instead, you can rely on the `apksigner` to verify the certificate chain.

The signing configuration can be managed through Android Studio or the `signingConfigs {}` block in `build.gradle`. The following values need to be set to activate both v1 and v2 scheme:

```
v1SigningEnabled true
v2SigningEnabled true
```

Several best practices to [configure the app for release](http://developer.android.com/tools/publishing/preparing.html#publishing-configure "") is also available in the official Android developer documentation.

#### Dynamic Analysis

Static analysis should be used to verify the APK signature.




### Testing If the App is Debuggable

#### Overview

The `android:debuggable` attribute in the [`Application`](https://developer.android.com/guide/topics/manifest/application-element.html "Application element") element in the manifest determines whether or not the app can be debugged when running on a user mode build of Android.

#### Static Analysis

Check in `AndroidManifest.xml` whether the `android:debuggable` attribute is set and it's value:

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.owasp">

    ...

    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <meta-data android:name="com.owasp.main" android:value=".Hook"/>
    </application>
</manifest>
```

In a release build, this attribute should always be set to "false" (the default value).

#### Dynamic Analysis

Drozer can be used to identify if an application is debuggable. The module `app.package.attacksurface` displays information about IPC components exported by the application, in addition to whether the app is debuggable.

```
dz> run app.package.attacksurface com.mwr.dz
Attack Surface:
  1 activities exported
  1 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

To scan for all debuggable applications on a device, the `app.package.debuggable` module should be used:

```
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

If an application is debuggable, it is trivial to get command execution in the context of the application. In `adb` shell, execute the `run-as` binary, followed by the package name and command:

```
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](http://developer.android.com/tools/debugging/debugging-studio.html "Debugging with Android Studio") can also be used to debug an application and verify if debugging is activated for an app.

Another alternative method to determine if an application is debuggable, is to attach `jdb` to the running process. If successful, debugging is activated.

The following procedure can be used to start a debug session using `jdb`:
- Identify, using `adb` and `jdwp`, the PID of the application that we want to debug and that is currently active on the device:

```
$ adb jdwp
2355
16346  <== last launched, corresponds to our application
```

- Create a communication channel by using `adb` between the application process (using the PID) and the analysis workstation on a specific local port:

```
# adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
$ adb forward tcp:55555 jdwp:16346
```

- Attach the debugger using `jdb` to the local communication channel port and start a debug session:

```
$ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> help
```

A few notes about debugging:
- The tool [`JADX`](https://github.com/skylot/jadx "JADX") can be used to identify interesting locations where breakpoints should be inserted.
- Help about [`JDB`](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm "JDB").
- If an error indicating that *the connection to the debugger has been closed* occur during the binding of `jdb` to the local communication channel port then kill all `adb` sessions and start a new single one.

### Testing for Debugging Symbols

#### Overview

As a general rule of thumb, as little explanative information as possible should be provided along with the compiled code. Some metadata such as debugging information, line numbers and descriptive function or method names make the binary or bytecode easier to understand for the reverse engineer, but isn’t actually needed in a release build and can therefore be safely discarded without impacting the functionality of the app.

For native binaries, use a standard tool like `nm` or `objdump` to inspect the symbol table. A release build should generally not contain any debugging symbols. If the goal is to obfuscate the library, removing unneeded dynamic symbols is also recommended.

#### Static Analysis

Symbols are usually stripped during the build process, so you need the compiled byte-code and libraries to verify whether any unnecessary metadata has been discarded.

First find the `nm` binary in your Android NDK and export it (or create an alias).

```bash
export $NM = $ANDROID_NDK_DIR/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm
```

To display debug symbols:

```bash
$ $NM -a libfoo.so
/tmp/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-nm: libfoo.so: no symbols
```

To display dynamic symbols:

```bash
$ $NM -D libfoo.so
```

Alternatively, open the file in your favorite disassembler and check the symbol tables manually.

Dynamic symbols can be stripped using the `visibility` compiler flag. Adding this flag causes gcc to discard the function names while still preserving the names of functions declared as `JNIEXPORT`.

Check if the following was added to build.gradle:

```
        externalNativeBuild {
            cmake {
                cppFlags "-fvisibility=hidden"
            }
        }
```

#### Dynamic Analysis

Static analysis should be used to verify for debugging symbols.

### Testing for Debugging Code and Verbose Error Logging

#### Overview

StrictMode is a developer tool to be able to detect policy violation, e.g. disk or network access.
It can be implemented in order to check for the usage of good coding practices such as implementing performant code or usage of network access on the main thread.

The policies are defined together with rules and different methods of showing the violation of a policy.

Here is [an example of `StrictMode`](https://developer.android.com/reference/android/os/StrictMode.html "StrictMode Class"), enabling both policies mentioned above:

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

It's recommended to insert the policy in the `if` statement with `DEVELOPER_MODE` as condition. The `DEVELOPER_MODE` has to be disabled for release build in order to disable `StrictMode` too.

#### Static Analysis

To check if `StrictMode` is enabled you could look for the methods `StrictMode.setThreadPolicy` or `StrictMode.setVmPolicy`. Most likely they will be in the onCreate() method.

The various [detect methods for the thread policy](http://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") are:

```
detectDiskWrites()
detectDiskReads()
detectNetwork()
```

The [possible penalties for thread policy](http://javabeat.net/strictmode-android-1/ "What is StrictMode in Android?") are:

```
penaltyLog() // Logs a message to LogCat
penaltyDeath() // Crashes application, runs at the end of all enabled penalties
penaltyDialog() // Show a dialog
```

Also have a look at the different [best practices](https://code.tutsplus.com/tutorials/android-best-practices-strictmode--mobile-7581 "Android Best Practices: StrictMode") when using StrictMode.

#### Dynamic Analysis

There are different ways of detecting  `StrictMode` and it depends on how the policies roles are implemented. Some of them are:

- Logcat
- Warning Dialog
- Crash of the application


### Testing for Injection Flaws

#### Overview

Android apps can expose functionality to:

- other apps via IPC mechanisms like Intents, Binders, Android Shared Memory (ASHMEM) or BroadcastReceivers,
- through custom URL schemes (which are part of Intents) and
- the user via the user interface.

All input that is coming from these different sources cannot be trusted and need to be validated and/or sanitized. Validation ensures that only data is processed that the app is expecting. If validation is not enforced any input can be sent to the app, which might allow an attacker or malicious app to exploit vulnerable functionalities within the app.


The source code should be checked if any functionality of the app is exposed, through:

- Custom URL schemes: check also the test case "Testing Custom URL Schemes"
- IPC Mechanisms (Intents, Binders, Android Shared Memory (ASHMEM) or BroadcastReceivers): check also the test case "Testing Whether Sensitive Data Is Exposed via IPC Mechanisms"
- User interface

An example for a vulnerable IPC mechanisms is listed below.

*ContentProviders* can be used to access database information, while services can be probed to see if they return data. If data is not validated properly the content provider might be prone to SQL injection when others apps are interacting with it. See the following vulnerable implementation of a *ContentProvider*.

```xml
<provider
    android:name=".OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation"
    android:authorities="sg.vp.owasp_mobile.provider.College">
</provider>
```

The `AndroidManifest.xml` above defines a content provider that is exported and therefore available for all other apps. In the `OMTG_CODING_003_SQL_Injection_Content_Provider_Implementation.java` class the `query` function should be inspected.

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

The query statement when providing a STUDENT_ID is prone to SQL injection, when accessing `content://sg.vp.owasp_mobile.provider.College/students`. Obviously [prepared statements](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet "OWASP SQL Injection Cheat Sheet") need to be used to avoid the SQL injection, but ideally also [input validation](https://www.owasp.org/index.php/Input_Validation_Cheat_Sheet "OWASP Input Validation Cheat Sheet") should be applied to only process input that the app is expecting.

All functions in the app that process data that is coming from external and through the UI should implement input validation:

- For input coming from the user interface [Android Saripaar v2](https://github.com/ragunathjawahar/android-saripaar "Android Saripaar v2") can be used.
- For input coming from IPC or URL schemes a validation function should be created. For example like the following that is checking if the [value is alphanumeric](https://stackoverflow.com/questions/11241690/regex-for-checking-if-a-string-is-strictly-alphanumeric "Input Validation").

```java
public boolean isAlphaNumeric(String s){
    String pattern= "^[a-zA-Z0-9]*$";
    return s.matches(pattern);
}
```

An alternative to validation functions are type conversion, like using `Integer.parseInt()` if only integer numbers are expected. The [OWASP Input Validation Cheat Sheet](https://www.owasp.org/index.php/Input_Validation_Cheat_Sheet "OWASP Input Validation Cheat Sheet") contains more information about this topic.

#### Dynamic Analysis

The tester should test manually the input fields with strings like "' OR 1=1--'" if for example a local SQL injection vulnerability can be identified.

When being on a rooted device the command content can be used to query the data from a Content Provider. The following command is querying the vulnerable function described above.

```
content query --uri content://sg.vp.owasp_mobile.provider.College/students
```

The SQL injection can be exploited by using the following command. Instead of getting the record for Bob all data can be retrieved.

```
content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''"
```

For dynamic testing Drozer can also be used.

### Testing Exception Handling

#### Overview

Exceptions can often occur when an application gets into a non-normal or erroneous state. Both in Java and C++ exceptions can be thrown when such state occurs.
Testing exception handling is about reassuring that the app will handle the exception and get to a safe state without exposing any sensitive information at both the UI and the logging mechanisms used by the app.

#### Static Analysis

Review the source code to understand and identify how the application handles various types of errors (IPC communications, remote services invocation, etc). Here are some examples of the checks to be performed at this stage :

- Verify that the application use a well-designed and unified scheme to [handle exceptions](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047 "Exceptional Behavior (ERR)").
- Verify that standard `RuntimeException`s (e.g.`NullPointerException`, `IndexOutOfBoundsException`, `ActivityNotFoundException`, `CancellationException`, `SQLException`) are anticipated upon by creating proper null-checks, bound-checks and alike. An [overview of the provided child-classes of `RuntimeException`](https://developer.android.com/reference/java/lang/RuntimeException.html "Runtime Exception Class") can be found in the Android developer documentation. If the developer still throws a child of `RuntimeException` then this should always be intentional and that intention should be handled by the calling method.
- Verify that for every non-runtime `Throwable`, there is a proper catch handler, which ends up handling the actual exception properly.
- When an exception is thrown, make sure that the application has centralized handlers for exceptions that result in similar behavior. This can be a static class for instance. For specific exceptions given the methods context, specific catch blocks should be provided.
- Verify that the application doesn't expose sensitive information while handling exceptions in its UI or in its log-statements, but are still verbose enough to explain the issue to the user.
- Verify that any confidential information, such as keying material and/or authentication information is always wiped at the `finally` blocks in case of a high risk application.

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

As a best practice a general exception-handler for uncaught exceptions can be added to clear out the state of the application prior to a crash:

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

Now the initializer need to be called for the handler at your custom `Application` class (e.g. the class that extends `Application`):

```java
	 @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        MemoryCleanerOnCrash.init();
    }
```

#### Dynamic Analysis

There are various ways of doing dynamic analysis:

- Use Xposed to hook into methods and call the method with unexpected values or overwrite existing variables to unexpected values (e.g. null values, etc.).
- Provide unexpected values to UI fields in the Android application.
- Interact with the application using its intents and public providers by using values that are unexpected.
- Tamper the network communication and/or the files stored by the application.

In all cases, the application should not crash, but instead, it should:

- Recover from the error or get into a state in which it can inform the user of not being able to continue.
- If necessary, inform the user in an informative message to make him/her take appropriate action. The message itself should not leak sensitive information.
- Not provide any information in logging mechanisms used by the application.


### Verify That Free Security Features Are Activated

#### Overview

As Java classes are trivial to decompile, applying some basic obfuscation to the release bytecode is recommended. For Java apps on Android, ProGuard offers an easy way to shrink and obfuscate code and to strip unneeded debugging information from the Java bytecode. It replaces identifiers such as class names, method names and variable names with meaningless character combinations. This is a form of layout obfuscation, which is “free” in that it doesn't impact the performance of the program.

Since most Android applications are Java based, they are [immune to buffer overflow vulnerabilities](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java "Java Buffer Overflows"). Nevertheless this vulnerability class can still be applicable when using the Android NDK, therefore secure compiler settings should be considered.

--ToDo Add content for secure compiler settings for Android NDK

#### Static Analysis

If source code is provided, the build.gradle file can be checked to see if obfuscation settings are applied. From the example below, you can see that `minifyEnabled` and `proguardFiles` are set. It is common to create exceptions for some classes from obfuscation with "-keepclassmembers" and "-keep class". Therefore it is important to audit the ProGuard configuration file to see what classes are exempted. The `getDefaultProguardFile('proguard-android.txt')` method gets the default ProGuard settings from the `<Android SDK>/tools/proguard/` folder. The file `proguard-rules.pro` is where you define custom ProGuard rules. From our sample `proguard-rules.pro` file, you can see that many classes that are extended are common Android classes, which should be done more granular on specific classes or libraries.

By default, ProGuard removes attributes that are useful for debugging, including line numbers, source file names and variable names. ProGuard is a free Java class file shrinker, optimizer, obfuscate and pre-verifier. It is shipped with Android’s SDK tools. To activate shrinking for the release build, add the following to build.gradle:

```
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
```
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
```

#### Dynamic Analysis

If source code is not provided, an APK can be decompiled to verify if the codebase has been obfuscated. Several tools are available to convert dex code to a jar file (dex2jar). The jar file can be opened in tools like JD-GUI that can be used to check if class, method and variable names are human readable.

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

### References

#### OWASP Mobile Top 10 2016

- M7 - Client Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

#### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."
- V7.1: "The app is signed and provisioned with valid certificate."
- V7.2: "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable)."
- V7.3: "Debugging symbols have been removed from native binaries."
- V7.4: "Debugging code has been removed, and the app does not log verbose errors or debugging messages."
- V7.6: "The app catches and handles possible exceptions."
- V7.7: "Error handling logic in security controls denies access by default."
- V7.9: "Free security features offered by the toolchain, such as byte-code minification, stack protection, PIE support and automatic reference counting, are activated."

#### CWE

- CWE-20 - Improper Input Validation
- CWE-215 - Information Exposure Through Debug Information
- CWE-388 - Error Handling
- CWE-489 - Leftover Debug Code
- CWE-656 - Reliance on Security Through Obscurity


#### Tools

- ProGuard - https://www.guardsquare.com/en/proguard
- jarsigner - http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html
- Xposed - http://repo.xposed.info/
- Drozer - https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf

- GNU nm - https://ftp.gnu.org/old-gnu/Manuals/binutils-2.12/html_node/binutils_4.html
