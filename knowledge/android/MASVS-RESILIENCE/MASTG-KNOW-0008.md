---
masvs_category: MASVS-RESILIENCE
platform: android
title: Obfuscation
---

The chapter ["Mobile App Tampering and Reverse Engineering"](0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) introduces several well-known obfuscation techniques that can be used in mobile apps in general.

Android apps can implement some of those obfuscation techniques using different tooling. For example, @MASTG-TOOL-0022 offers an easy way to shrink and obfuscate code and to strip unneeded debugging information from the bytecode of Android Java apps. It replaces identifiers, such as class names, method names, and variable names, with meaningless character strings. This is a type of layout obfuscation, which doesn't impact the program's performance.

> Decompiling Java classes is trivial, therefore it is recommended to always applying some basic obfuscation to the production bytecode.

Learn more about Android obfuscation techniques:

- ["Security Hardening of Android Native Code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) by Gautam Arvind
- ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) by Eduardo Novella (@MASTG-TOOL-0009)
- ["Challenges of Native Android Applications: Obfuscation and Vulnerabilities"](https://www.theses.fr/2020REN1S047.pdf) by Pierre Graux

## Using ProGuard

Developers use the build.gradle file to enable obfuscation. In the example below, you can see that `minifyEnabled` and `proguardFiles` are set. Creating exceptions to protect some classes from obfuscation (with `-keepclassmembers` and `-keep class`) is common. Therefore, auditing the ProGuard configuration file to see what classes are exempted is important. The `getDefaultProguardFile('proguard-android.txt')` method gets the default ProGuard settings from the `<Android SDK>/tools/proguard/` folder.

Further information on how to shrink, obfuscate, and optimize your app can be found in the [Android developer documentation](https://developer.android.com/studio/build/shrink-code "Shrink, obfuscate, and optimize your app").

> When you build your project using Android Studio 3.4 or Android Gradle plugin 3.4.0 or higher, the plugin no longer uses ProGuard to perform compile-time code optimization. Instead, the plugin uses the R8 compiler. R8 works with all of your existing ProGuard rules files, so updating the Android Gradle plugin to use R8 should not require you to change your existing rules.

R8 is the new code shrinker from Google and was introduced in Android Studio 3.3 beta. By default, R8 removes attributes that are useful for debugging, including line numbers, source file names, and variable names. R8 is a free Java class file shrinker, optimizer, obfuscator, and pre-verifier and is faster than ProGuard, see also an [Android Developer blog post for further details](https://android-developers.googleblog.com/2018/11/r8-new-code-shrinker-from-google-is.html "R8"). It is shipped with Android's SDK tools. To activate shrinking for the release build, add the following to build.gradle:

```default
android {
    buildTypes {
        release {
            // Enables code shrinking, obfuscation, and optimization for only
            // your project's release build type.
            minifyEnabled true

            // Includes the default ProGuard rules files that are packaged with
            // the Android Gradle plugin. To learn more, go to the section about
            // R8 configuration files.
            proguardFiles getDefaultProguardFile(
                    'proguard-android-optimize.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

The file `proguard-rules.pro` is where you define custom ProGuard rules. With the flag `-keep` you can keep certain code that is not being removed by R8, which might otherwise produce errors. For example to keep common Android classes, as in our sample configuration `proguard-rules.pro` file:

```default
...
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
...
```

You can define this more granularly on specific classes or libraries in your project with the [following syntax](https://developer.android.com/studio/build/shrink-code#configuration-files "Customize which code to keep"):

```default
-keep public class MyClass
```

Obfuscation often carries a cost in runtime performance, therefore it is usually only applied to certain very specific parts of the code, typically those dealing with security and runtime protection.
