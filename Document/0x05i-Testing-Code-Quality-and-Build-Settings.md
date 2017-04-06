## Testing Code Quality and Build Settings

### Verifying That the App is Properly Signed

#### Overview

Android requires that all APKs be digitally signed with a certificate before they can be installed. The digital signature is required by the Android system before installing/running an application, and it's also used to verify the identity of the owner for future updates of the application. This process can prevents an app from being tampered with, or modified to include malicious code.

When an is signed APK, a public-key certificate is attached to the APK. This certificate uniquely associates the APK to the developer and their corresponding private key. When building an app in debug mode, the Android SDK signs the app with a debug key specifically created for debugging purposes. An app signed with a debug key is not be meant for distribution and won't be accepted in most app stores, including the Google Play Store. To prepare the app for final release, the app must be signed with a release key belonging to the developer.

When testing the final release build of an app, you should verify that the APK has been signed with a valid certificate. Note that Android expects any updates to the app to be signed with the same certificate, so a validity period of 25 years or more is recommended. Apps published on Google Play must be signed with a certificate that is valid at least until October 22th, 2033.

#### White-box Testing


#### Black-box Testing

-- TODO [Add content for black-box testing of "Verifying That the App is Properly Signed"] --

#### Remediation

-- TODO [Add content for remediation of "Verifying That the App is Properly Signed"] --

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V7.1: "The app is signed and provisioned with valid certificate."

##### CWE

-- TODO [Add relevant CWE for "Verifying That the App is Properly Signed"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Verifying That the App is Properly Signed"] --
* Enjarify - https://github.com/google/enjarify


### Testing If the App is Debuggable

#### Overview

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### White-box Testing

Check the AndroidManifest.xml for the value of "android:debuggable" attribute within the application element:

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.android.owasp">

    ...

    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
        <meta-data android:name="com.owasp.main" android:value=".Hook"/>
    </application>
</manifest>
```

This setting specifies whether or not the application can be debugged, even when running on a device in user mode. A value of "true" defines that debugging is activated and "false" means debugging is deactivated. The default value is "false".

Although the `android:debuggable=""` flag can be bypassed by repacking the application, before shipping it, it is important to set the option `android:debuggable="false"` in the _AndroidManifest.xml_.

A comprehensive guide to debug an Android application can be found within the official documentation by Android (see references).

#### Black-box Testing

When targeting a compiled Android application, the most reliable method is to first decompile it in order to obtain the AndroidManifest.xml file (see Decompiling Android App Guide - #TODO-Create a general guide that can bee referenced anywhere in the MSTG) and check the value of "android:debuggable" attribute.

Otherwise, use the Android Asset Packaging Tool (aapt) to check the debuggable flag :

```
$ aapt l -a /path/to/apk/file.apk | grep debuggable
```

Will return the following if android:debuggable parameter is set to true :

```
      A: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
```


Attempt to attach a debugger to the running process. This  should either fail, or the app should terminate or misbehave when the debugger has been detected. For example, if ptrace(PT_DENY_ATTACH) has been called, gdb will crash with a segmentation fault:

-- TODO [Add an example of black-box testing of "Testing If the App is Debuggable"] --

-- TODO [Add elements on Java Debug Wire Protocol (JDWP)] --

Note that some anti-debugging implementations respond in a stealthy way so that changes in behaviour are not immediately apparent. For example, a soft token app might not visibly respond when a debugger is detected, but instead secretly alter the state of an internal variable so that an incorrect OTP is generated at a later point. Make sure to run through the complete workflow to determine if attaching the debugger causes a crash or malfunction.

#### Remediation

For production releases, the attribute android:debuggable must be set to false within the application element. This ensures that a debugger cannot attach to the process of the application.

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing If the App is Debuggable"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing If the App is Debuggable"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Testing If the App is Debuggable"] --
* Enjarify - https://github.com/google/enjarify


### Testing for Debugging Symbols

#### Overview

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### White-box Testing

-- TODO [Add content on white-box testing of "Testing for Debugging Symbols"] --

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

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Debugging Symbols"] --

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing for Debugging Symbols"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing for Debugging Symbols"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Testing for Debugging Symbols"] --
* Enjarify - https://github.com/google/enjarify


### Testing for Debugging Code and Verbose Error Logging

#### Overview

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### White-box Testing

-- TODO [Add content on white-box testing for "Testing for Debugging Code and Verbose Error Logging"] --

#### Black-box Testing

-- TODO [Add content on black-box testing for "Testing for Debugging Code and Verbose Error Logging"] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Debugging Code and Verbose Error Logging"] --

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing for Debugging Code and Verbose Error Logging"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing for Debugging Code and Verbose Error Logging"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Testing for Debugging Code and Verbose Error Logging"] --
* Enjarify - https://github.com/google/enjarify


### Testing Exception Handling

#### Overview

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### White-box Testing

Review the source code to understand/identify who the application handle various types of errors (IPC communications, remote services invokation, etc). Here are some examples of the checks to be performed at this stage :

* Verify that the application use a [well-designed] (https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=18581047) (an unified) scheme to handle exceptions.
* Verify that the application doesn't expose sensitive information while handeling exceptions, but are still verbose enough to explain the issue to the user.
* C3

#### Black-box Testing

-- TODO [Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Exception Handling"] --

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Testing Exception Handling"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Testing Exception Handling"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Testing Exception Handling"] --
* Enjarify - https://github.com/google/enjarify


### Verifying Compiler Settings

#### Overview

Since most Android applications are Java based, they are [immunue](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows#.NET_.26_Java) to buffer overflow vulnerabilities.

#### White-box Testing

-- TODO [Describe how to assess this with access to the source code and build configuration] --

#### Black-box Testing

-- TODO [Describe how to test for this issue using static and dynamic analysis techniques. This can include everything from simply monitoring aspects of the app’s behavior to code injection, debugging, instrumentation, etc. ] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying Compiler Settings"] --

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference "VX.Y" below for "Verifying Compiler Settings"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for "Verifying Compiler Settings"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Verifying Compiler Settings"] --
* Enjarify - https://github.com/google/enjarify


### Testing for Memory Management Bugs

#### Overview

-- TODO [Give an overview about the functionality and it's potential weaknesses] --

#### White-box Testing

-- TODO [Add content for white-box testing "Testing for Memory Management Bugs"] --

#### Black-box Testing

-- TODO [Add content for black-box testing "Testing for Memory Management Bugs"] --

#### Remediation

-- TODO [Add remediations for "Testing for Memory Management Bugs"] --

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- V7.7: "In unmanaged code, memory is allocated, freed and used securely."

##### CWE

-- TODO [Add relevant CWE for "Testing for Memory Management Bugs"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for "Testing for Memory Management Bugs"] --
* Enjarify - https://github.com/google/enjarify


### Verifying that Java Bytecode Has Been Minified

#### Overview

Because Java classes are trivial to decompile, applying some basic obfuscation to the release bytecode is recommended. For Java apps on Android, ProGuard offers an easy way to shrink and obfuscate code. It replaces identifiers such as  class names, method names and variable names with meaningless character combinations. This is a form of layout obfuscation, which is “free” in that it doesn't impact the performance of the program.

#### White-box Testing

If source code is provided, build.gradle file can be check to see if obfuscation settings are set. From the example below, we can see that minifyEnabled and proguardFiles are set. It is common to see application exempts some class from obfuscation with "-keepclassmembers" and "-keep class", so it is important to audit proguard configuration file to see what class are exempted. The getDefaultProguardFile('proguard-android.txt') method gets the default ProGuard settings from the Android SDK tools/proguard/ folder and proguard-rules.pro is where you defined custom proguard rules. From our sample proguard-rules.pro file, we can see that many classes that extend common android classes are exempted, which should be done more granular on exempting specific classes or library.

build.gradle
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

#### Black-box Testing

If source code is not provided, apk can be decompile to verify if codebase have been obfuscated. dex2jar can be used to convert dex code to jar file. Tools like JD-GUI can be used to check if class, method and variable name is human readable.

Sample obfuscated code block
```
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

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Verifying that Java Bytecode Has Been Minified"] --
- VX.Y: ""

##### CWE

-- TODO [Add relevant CWE for Verifying that Java Bytecode Has Been Minified] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

* Configuring your application for release - http://developer.android.com/tools/publishing/preparing.html#publishing-configure
* Debugging with Android Studio - http://developer.android.com/tools/debugging/debugging-studio.html

##### Tools

-- TODO [Add relevant tools for Verifying that Java Bytecode Has Been Minified] --
* Enjarify - https://github.com/google/enjarify


