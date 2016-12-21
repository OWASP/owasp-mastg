### <a name="OMTG-CODE-001"></a>OMTG-CODE-001: Verify that the App is Properly Signed

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

#### References

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### OWASP MASVS

- V7.1: "The app is signed and provisioned with valid certificate."

### <a name="OMTG-CODE-002"></a>OMTG-CODE-002: Test If the App is Debuggable

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

Check the AndroidManifest.xml for the value of "android:debuggable" attribute within the application element :

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.owasp">

    ...

    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <meta-data android:name="com.owasp.main" android:value=".Hook"/>
    </application>
</manifest>
```

This setting specifies whether or not the application can be debugged, even when running on a device in user mode. A value of "true" if it can be, And "false" if not. The default value is "false".

Although the `android:debuggable=""` flag can be bypassed by repacking the application, before shipping it, it is important to set the option `android:debuggable="false"` in the _AndroidManifest.xml_.

A comprehensive guide to debug an Android application can be found within the official documentation by Android (see references).

#### Black-box Testing

##### Static Test

When targeting a compiled Android application, the most reliable method is to first decompile it in order to obtain the AndroidManifest.xml file (see Decompiling Android App Guide - #TODO-Create a general guide that can bee referenced anywhere in the OMSTF) and check the value of "android:debuggable" attribute.

Otherwise, use the Android Asset Packaging Tool (aapt) to check the debuggable flag :

```
$ aapt l -a /path/to/apk/file.apk | grep debuggable
```

Will return the following if android:debuggable parameter is set to true :

```
      A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
```

##### Dynamic Test

Attempt to attach a debugger to the running process. This  should either fail, or the app should terminate or misbehave when the debugger has been detected. For example, if ptrace(PT_DENY_ATTACH) has been called, gdb will crash with a segmentation fault:

(TODO example)

(TODO JDWP)

Note that some anti-debugging implementations respond in a stealthy way so that changes in behaviour are not immediately apparent. For example, a soft token app might not visibly respond when a debugger is detected, but instead secretly alter the state of an internal variable so that an incorrect OTP is generated at a later point. Make sure to run through the complete workflow to determine if attaching the debugger causes a crash or malfunction.

#### Remediation

For production releases, the attribute android:debuggable must be set to false within the application element. This ensures that a debugger cannot attach to the process of the application.

#### References

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

### <a name="OMTG-CODE-003"></a>OMTG-CODE-003: Test for Debugging Symbols

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

Symbols  are usually stripped during the build process, so you need the compiled bytecode and libraries to verify whether the any unnecessary metadata has been discarded. For native binaries, use a standard tool like nm or objdump to inspect the symbol table. For example:

~~~~
berndt@osboxes:~/ $ objdump -t my_library.so
my_library.so:     file format elf32-little

SYMBOL TABLE:
no symbols
~~~~

Alternatively, open the file in your favorite disassembler and look for debugging symbols. For native libraries, it should be checked that the names of exports don’t give away the location of sensitive functions.

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-004"></a>OMTG-CODE-004: Test for Debugging Code and Verbose Error Logging

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-005"></a>OMTG-CODE-005: Test Exception Handling

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

Review the source code to understand/identify who the application handle various types of errors (IPC communications, remote services invokation, etc). Here are some examples of the checks to be performed at this stage :

* Verify that the application use a [well-designed] (https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (an unified) scheme to handle exceptions.
* Verify that the application doesn't expose sensitive information while handeling exceptions, but are still verbose enough to explain the issue to the user.
* C3

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-006"></a>OMTG-CODE-006: Verify that the App Fails Securely

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-007"></a>OMTG-CODE-007: Test Input Validation

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-008"></a>OMTG-CODE-008: Test Memory Management

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-009"></a>OMTG-CODE-009: Test Compiler Settings

#### Overview

Since most Android applications are Java based, they are [immunue](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java) to buffer overflow vulnerabilities.

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-CODE-010"></a>OMTG-CODE-010: Verify that Java Bytecode Has Been Minifed

#### Overview

Because Java classes are trivial to decompile, applying some basic obfuscation to the release bytecode is recommended. For Java apps on Android, ProGuard offers an easy way to shrink and obfuscate code. It replaces identifiers such as  class names, method names and variable names with meaningless character combinations. This is a form of layout obfuscation, which is “free” in that it doesn't impact the performance of the program.

#### White-box Testing

Verify the minifyEnabled is set to true in build.gradle (see below).

#### Black-box Testing

[Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ]

#### Remediation

ProGuard should be used to strip unneeded debugging information from the Java bytecode. By default, ProGuard removes attributes that are useful for debugging, including line numbers, source file names and variable names. ProGuard is a free Java class file shrinker, optimizer, obfuscator, and preverifier. It is shipped with Android’s SDK tools. To activate shrinking for the release build, add the following to build.gradle:

~~~~
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile(‘proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
~~~~

#### References

- [link to relevant how-tos, papers, etc.]
