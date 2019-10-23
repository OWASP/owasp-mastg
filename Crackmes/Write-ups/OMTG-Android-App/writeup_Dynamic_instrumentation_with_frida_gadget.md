# Dynamic instrumentation with frida gadget

> Author: Jon-Anthoney de Boer

## What is the frida gadget

At a high-level, [frida][Frida] is a dynamic binary instrumentation toolset that enables security testers to `hook` into applications and inspect or alter their behaviour at runtime. 

The frida CLI; itself installed on the test workstation, can be used in communication with the [frida server][FridaServer]. The frida server is a component that can be loaded onto a test device when the test device is rooted, as it requires elevated permissions to function as intended. This component enables the instrumentation of the target application running on the test device. 

The frida CLI can also be used in comunication with the [frida gadget][FridaGadget]. The frida gadget is a component that achieves similar functionality as the frida server, but does so where the test device is not rooted. 

The use of the frida gadget, to enable dynamic binary instrumentation of a target application on a non-rooted test device, is the focus of this write-up. 

## Why use the frida gadget?

It can be useful to be able to utilise a non-rooted test device when carrying out security testing of an android application for a variety of reasons. This can be achieved by injecting the frida gadget into a target application to provide support for dynamic binary instrumentation. The steps required to instrument the target application are a little more involved when making use of the frida gadget on a non-rooted device than they are where the tester has recourse to a rooted test device and so can make use of the frida server component.

This write-up is crafted with reference to the [OWASP Crackme Level 1 app][OWASPCrackMeLevel1] as a convenient target application, and is based upon the excellent information found in various resources that are available online. Some references are listed at the end of this write-up.

## What will we learn?

Broadly, through following this write-up the reader will learn:
- how to decompose a target application from APK to source and resources.
- how to inject and initialise the frida gadget into the decomposed target application.
- how to rebuild the target application back into a useful APK.
- how to confirm communcation between frida on the tester's workstation and the frida gadget as injected within the target application that is deployed to a non-rooted test device. 

## Preparation

We will work with the [OMTG Crackme Level 1 app][OWASPCrackMeLevel1]. For convenience, this write-up will reuse either of the android emulators that may have been configured as a part of the [Diving into mobile cryptography using dynamic instrumentation][OWASPDivingIntoCryptoWithDynamicInstrumentation] write-up.

>Note: frida CLI and frida gadget versions must match

The specific version of frida tooling that you've installed on your workstation must match the version of frida gadget that you download and inject into your target application. 
  
This guide is written to expect alignment at `12.11.7`. Substitute `12.11.7` with your specific version as needed.

## Goal

The goal is for the reader to be able to decompose a target application from APK to source and resources. Then, inject the frida gadget into the application and initialise it early in the target application's initialisation sequence. Next, repackage the target application back into an APK for deployment to a test device. Finally, confirm that communication is establised between frida on the tester's workstation and the frida gadget as injected within the target application. 

## Let's get started
There are four broad stages involved in preparing for testing of a target application on a non-rooted device via dynamic binary injection using the frida gadget. These are:
- Initial setup and decomposition
- Injection and initialision
- Repackaging and deployment 
- Verification and use

> Please ensure your test device is powered on and connected to your workstation

### Initial setup and decomposition
At this stage, the reader will download and decompress required artifacts, confirm connectivity between the tester's workstation and the test device, and decompose the target APK into source and resources. 

Move your terminal to a suitable working directory to begin:
```
$ cd ~/crackmes
```

Download [OWASP Crackme Level 1 app][OWASPCrackMeLevel1], which will be used as the target application for this exercise:
```
$ curl -O https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
```

Confirm that the test device is available:
```
$ adb devices -l
List of devices attached
emulator-5554          device product:sdk_phone_x86_64 model:Android_SDK_built_for_x86_64 device:generic_x86_64 transport_id:11
```

Confirm the CPU architecture of the test device:
```
$ adb shell getprop ro.product.cpu.abi
> x86_64
```

Download the appropriate version of the frida gadget to suit the test device and the frida version as installed on the tester's workstation:
```
$ curl -O https://github.com/frida/frida/releases/download/12.7.11/frida-gadget-12.7.11-android-x86_64.so.xz
```

Decompress the frida gadget archive that was retrieved. Either execute:
```
$ unxz frida-gadget-12.7.11-android-x86_64.so.xz
```
Or:
```
$ xz -d frida-gadget-12.7.11-android-x86_64.so.xz
```
>Note: it can be convenient to make use of MacOS' Unarchiver utility if a `File format` error is encountered when attempting to decompress the frida gadget archive.

Decompose the target application into which the frida gadget will be injected
```
$ apktool d UnCrackable-Level1.apk -o uncrackableLevel1Gadget
```

### Injection and initialision
At this stage, the reader will inject the frida gadget into the decomposed target application, and ensure it will be initialised early.

If not already existing, ensure the `lib/<CPU_ARCH>` directory is present within the decomposed target application:
```
$ mkdir uncrackableLevel1Gadget/lib
$ mkdir uncrackableLevel1Gadget/lib/x86_64
```

Copy the decompressed frida gadget into the `lib/<CPU_ARCH>` directory within the decomposed target application. Note that the gadget will need to be renamed; here it is named `libfrida-gadget.so`, this is to suit certain conditions imposed by the android package manager:
```
$ cp frida-gadget-12.7.11-android-x86_64.so uncrackableLevel1Gadget/lib/x86_64/libfrida-gadget.so
```

Initialise the frida gadget within the decomposed application, by calling `System.loadLibrary()` as early as possible. As it can be observed that `MainActivity` is defined as an entrypoint within the decomposed target application's `AndroidManifest.xml`, it is possible to add the following smali code to this class's `.method public constructor <init>()V` method:
```
# increment .locals by 1, as we make use of a new string to identify our gadget by name
.locals 1

# Make the System.loadLibrary() call that will load the frida gadget 
const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

Ensure that `INTERNET` permission is present within the decomposed target application's `AndroidManifest.xml`:
```
<uses-permission android:name="android.permission.INTERNET" />
```

Increment the target application's version in the `apktool.yml` file that is produced when using `apktool` to decompose:
```
versionInfo:
  versionCode: '2' # originally '1'
```

### Repackaging and deployment 
At the stage, the reader will run through the sequence of steps necessary to rebuild the target application back into an APK that can be successfully installed onto the test device.

Rebuild the target application, noting that the frida gadget has now been injected:
```
$ apktool b uncrackableLevel1Gadget
```

Copy the rebuilt target application APK back to the working directory, ready for further processing:
```
$ cp uncrackableLevel1Gadget/dist/UnCrackable-Level1.apk ./UnCrackable-Level1-gadget.apk
```

Zipalign the rebuilt target application APK:
$ zipalign -p 4 UnCrackable-Level1-gadget.apk UnCrackable-Level1-gadget-aligned.apk

> Note: if a keystore has not yet been set up on the test workstation, set one up: 
```
$ keytool -genkey -alias fridaDemokeystore -keystore fridaDemoKeyStore.pfx -storetype PKCS12 -keyalg RSA -validity 365 -keysize 2048
```

Re-sign the rebuilt target application APK:
```
$ apksigner sign --ks fridaDemoKeyStore.pfx UnCrackable-Level1-gadget-aligned.apk
```

Install the re-signed target application APK onto the test device:
```
$ adb install UnCrackable-Level1-gadget-aligned.apk
```

### Verification and use 
At this stage, the reader will prove interaction with the frida gadget; as injected within the target application on the test device, from frida on the tester's workstation.

On the test device, tap to open the target application that has been injected with the frida gadget. You should see logging similar to the following in logcat:
```
2019-10-22 23:01:21.648 2684-2699/owasp.mstg.uncrackable1 I/Frida: Listening on 127.0.0.1 TCP port 27042
```

Confirm the frida gadget is in place within the target application on the test device:
```
$ frida -U gadget
     ____
    / _  |   Frida 12.7.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/

[Android Emulator 5554::gadget]-> Java.available
true
[Android Emulator 5554::gadget]->
```
The mechanism for interaction with the target application from the tester's workstation is now confirmed. 

Finally, it is possible for the tester to make use of a hooking script when carrying out security testing. Here, it is assumed that a file named `hook_uncrackable1.js` exists within the working directory of the tester's workstation.
```
$ frida -U gadget -l hook_uncrackable1.js
     ____
    / _  |   Frida 12.7.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Attaching...
[*] script 'hook_uncrackable1.js' loaded
[*] <REDACTED CRACKME TRACING> modified
<REDACTED CRACKME TRACING>
[Android Emulator 5554::gadget]-> exit

Thank you for using Frida!
$
```
## Conclusion

It is possible to make use of frida for dynamic binary instrumentation of a target android application - even without recourse to a rooted test device - using the frida gadget. Happy days =)

## Next steps

At this point, you have worked through a set of specific steps required to inject the frida gadget into a target application and understand the process involved. Conveniently, there are resources available that can automate this process - such as with [objection][patchingwithobjection]. Try it out. 

## References
- [FRIDA Gadget](https://www.frida.re/docs/gadget/)
- [Diving into mobile cryptography using dynamic instrumentation with frida](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Write-ups/OMTG-Android-App/writeup_Diving_into_mobile_cryptography_using_dynamic_instrumentation_with_frida.md)
- [How to use frida on a non-rooted device](https://lief.quarkslab.com/doc/latest/tutorials/09_frida_lief.html)
- [Using Frida on Android without root](https://koz.io/using-frida-on-android-without-root/)
- [objection - patching android applications](https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk)
___

[patchingwithobjection]: https://github.com/sensepost/objection/wiki/Patching-Android-Applications#patching---patching-an-apk
[OWASPCrackMeLevel1]: https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk
[OWASPDivingIntoCryptoWithDynamicInstrumentation]: https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Write-ups/OMTG-Android-App/writeup_Diving_into_mobile_cryptography_using_dynamic_instrumentation_with_frida.md
[Frida]: https://frida.re
[FridaGadget]: https://www.frida.re/docs/gadget/
[FridaServer]: https://www.frida.re/docs/modes/#injected
