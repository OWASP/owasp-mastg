# iOS Tampering and Reverse Engineering

## Reverse Engineering

iOS reverse engineering is a mixed bag. On one hand, apps programmed in Objective-C and Swift can be disassembled nicely. In Objective-C, object methods are called via dynamic function pointers called "selectors", which are resolved by name during runtime. The advantage of runtime name resolution is that these names need to stay intact in the final binary, making the disassembly more readable. Unfortunately, this also means that no direct cross-references between methods are available in the disassembler and constructing a flow graph is challenging.

In this guide, we'll introduce static and dynamic analysis and instrumentation. Throughout this chapter, we refer to the [OWASP UnCrackable Apps for iOS](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes#ios "OWASP UnCrackable Apps for iOS"), so download them from the MSTG repository if you're planning to follow the examples.

### Disassembling and Decompiling

Because Objective-C and Swift are fundamentally different, the programming language in which the app is written affects the possibilities for reverse engineering it. For example, Objective-C allows method invocations to be changed at runtime. This makes hooking into other app functions (a technique heavily used by [Cycript](http://www.cycript.org/ "Cycript") and other reverse engineering tools) easy. This "method swizzling" is not implemented the same way in Swift, and the difference makes the technique harder to execute with Swift than with Objective-C.

On iOS, all the application code (both Swift and Objective-C) is compiled to machine code (e.g. ARM). Thus, to analyze iOS applications a disassembler is needed.

If you want to disassemble an application from the App Store, remove the Fairplay DRM first. Section "[Acquiring the App Binary](0x06b-Basic-Security-Testing.md#acquiring-the-app-binary "Acquiring the App Binary")" in the chapter "iOS Basic Security Testing" explains how.

In this section the term "app binary" refers to the Macho-O file in the application bundle which contains the compiled code, and should not be confused with the application bundle - the IPA file. See section "[Exploring the App Package](0x06b-Basic-Security-Testing.md#exploring-the-app-package "Exploring the App Package")" in chapter "Basic iOS Security Testing" for more details on the composition of IPA files.

#### Disassembling With IDA Pro

If you have a license for IDA Pro, you can analyze the app binary using IDA Pro as well.

> The free version of IDA unfortunately does not support the ARM processor type.

To get started, simply open the app binary in IDA Pro.

![IDA Pro open a Mach-O file](Images/Chapters/0x06c/ida_macho_import.png) \

Upon opening the file, IDA Pro will perform auto-analysis, which can take a while depending on the size of the binary. Once the auto-analysis is completed you can browse the disassembly in the **IDA View** (Disassembly) window and explore functions in the **Functions** window, both shown in the screenshot below.

![IDA Pro main window](Images/Chapters/0x06c/ida_main_window.png) \

A regular IDA Pro license does not include a decompiler by default and requires an additional license for the Hex-Rays decompiler, which is expensive. In contrast, Ghidra comes with a very capable free builtin decompiler, making it a compelling alternative to use for reverse engineering.

If you have a regular IDA Pro license and do not want to buy the Hex-Rays decompiler, you can use Ghidra's decompiler by installing the [GhIDA plugin](https://github.com/Cisco-Talos/GhIDA/) for IDA Pro.

The majority of this chapter applies to applications written in Objective-C or having bridged types, which are types compatible with both Swift and Objective-C. The Swift compatibility of most tools that work well with Objective-C is being improved. For example, Frida supports [Swift bindings](https://github.com/frida/frida-swift "Frida-swift").

## Static Analysis

The preferred method of statically analyzing iOS apps involves using the original Xcode project files. Ideally, you will be able to compile and debug the app to quickly identify any potential issues with the source code.

Black box analysis of iOS apps without access to the original source code requires reverse engineering. For example, no decompilers are available for iOS apps (although most commercial and open-source disassemblers can provide a pseudo-source code view of the binary), so a deep inspection requires you to read assembly code.

### Basic Information Gathering

In this section, we will learn about some approaches and tools for collecting basic information about a given application using static analysis.

#### Application Binary

You can use [class-dump](0x08-Testing-Tools.md#class-dump) to get information about methods in the application's source code. The example below uses the [Damn Vulnerable iOS App](http://damnvulnerableiosapp.com/ "Damn Vulnerable iOS App") to demonstrate this. Our binary is a so-called fat binary, which means that it can be executed on 32- and 64-bit platforms:

```bash
$ unzip DamnVulnerableiOSApp.ipa

$ cd Payload/DamnVulnerableIOSApp.app

$ otool -hv DamnVulnerableIOSApp

DamnVulnerableIOSApp (architecture armv7):
Mach header
     magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
  MH_MAGIC     ARM         V7  0x00     EXECUTE    38       4292   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE

DamnVulnerableIOSApp (architecture arm64):
Mach header
     magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64   ARM64        ALL  0x00     EXECUTE    38       4856   NOUNDEFS DYLDLINK TWOLEVEL WEAK_DEFINES BINDS_TO_WEAK PIE

```

Note the architectures: `armv7` (which is 32-bit) and `arm64`. This design of a fat binary allows an application to be deployed on all devices.
To analyze the application with class-dump, we must create a so-called thin binary, which contains one architecture only:

```bash
iOS8-jailbreak:~ root# lipo -thin armv7 DamnVulnerableIOSApp -output DVIA32
```

And then we can proceed to performing class-dump:

```bash
iOS8-jailbreak:~ root# class-dump DVIA32

@interface FlurryUtil : ./DVIA/DVIA/DamnVulnerableIOSApp/DamnVulnerableIOSApp/YapDatabase/Extensions/Views/Internal/
{
}
+ (BOOL)appIsCracked;
+ (BOOL)deviceIsJailbroken;
```

Note the plus sign, which means that this is a class method that returns a BOOL type.
A minus sign would mean that this is an instance method. Refer to later sections to understand the practical difference between these.

Alternatively, you can easily decompile the application with [Hopper Disassembler](https://www.hopperapp.com/ "Hopper Disassembler"). All these steps would be executed automatically, and you'd be able to see the disassembled binary and class information.

The following command is listing shared libraries:

```bash
$ otool -L <binary>
```

#### Retrieving Strings

Strings are always a good starting point while analyzing a binary, as they provide context to the associated code. For instance, an error log string such as "Cryptogram generation failed" gives us a hint that the adjoining code might be responsible for the generation of a cryptogram.

In order to extract strings from an iOS binary, you can use GUI tools such as Ghidra or Cutter or rely on CLI-based tools such as the _strings_ Unix utility (`strings <path_to_binary>`) or radare2's rabin2 (`rabin2 -zz <path_to_binary>`). When using the CLI-based ones you can take advantage of other tools such as grep (e.g. in conjunction with regular expressions) to further filter and analyze the results.

#### Cross References

Ghidra can be used for analyzing the iOS binaries and obtaining cross references by right clicking the desired function and selecting **Show References to**.

#### API Usage

The iOS platform provides many built-in libraries for frequently used functionalities in applications, for example cryptography, Bluetooth, NFC, network and location libraries. Determining the presence of these libraries in an application can give us valuable information about its underlying working.

For instance, if an application is importing the `CC_SHA256` function, it indicates that the application will be performing some kind of hashing operation using the SHA256 algorithm. Further information on how to analyze iOS's cryptographic APIs is discussed in the section "[iOS Cryptographic APIs](0x06e-Testing-Cryptography.md "iOS Cryptographic APIs")".

Similarly, the above approach can be used to determine where and how an application is using Bluetooth. For instance, an application performing communication using the Bluetooth channel must use functions from the Core Bluetooth framework such as `CBCentralManager` or `connect`. Using the [iOS Bluetooth documentation](https://developer.apple.com/documentation/corebluetooth "iOS Bluetooth documenation") you can determine the critical functions and start analysis around those function imports.

#### Network Communication

Most of the apps you might encounter connect to remote endpoints. Even before you perform any dynamic analysis (e.g. traffic capture and analysis), you can obtain some initial inputs or entry points by enumerating the domains to which the application is supposed to communicate to.

Typically these domains will be present as strings within the binary of the application. One can extract domains by retrieving strings (as discussed above) or checking the strings using tools like Ghidra. The latter option has a clear advantage: it can provide you with context, as you'll be able to see in which context each domain is being used by checking the cross-references.

From here on you can use this information to derive more insights which might be of use later during your analysis, e.g. you could match the domains to the pinned certificates or perform further reconnaissance on domain names to know more about the target environment.

The implementation and verification of secure connections can be an intricate process and there are numerous aspects to consider. For instance, many applications use other protocols apart from HTTP such as XMPP or plain TCP packets, or perform certificate pinning in an attempt to deter MITM attacks.

Remember that in most cases, only using static analysis will not be enough and might even turn to be extremely inefficient when compared to the dynamic alternatives which will get much more reliable results (e.g. using an interceptor proxy). In this section we've just slightly touched the surface, so please refer to the section "[Basic Network Monitoring/Sniffing](0x06b-Basic-Security-Testing.md#basic-network-monitoringsniffing "Basic Network Monitoring/Sniffing")" in the "iOS Basic Security Testing" chapter and check out the test cases in the chapter "[iOS Network APIs](0x06g-Testing-Network-Communication.md "iOS Network APIs")" for further information.

### Manual (Reversed) Code Review

#### Reviewing Disassembled Objective-C and Swift Code

In this section we will be exploring iOS application's binary code manually and perform static analysis on it. Manual analysis can be a slow process and requires immense patience. A good manual analysis can make the dynamic analysis more successful.

There are no hard written rules for performing static analysis, but there are few rules of thumb which can be used to have a systematic approach to manual analysis:

- Understand the working of the application under evaluation - the objective of the application and how it behaves in case of wrong input.
- Explore the various strings present in the application binary, this can be very helpful, for example in spotting interesting functionalities and possible error handling logic in the application.
- Look for functions and classes having names relevant to our objective.
- Lastly, find the various entry points into the application and follow along from there to explore the application.

> Techniques discussed in this section are generic and applicable irrespective of the tools used for analysis.

##### Objective-C

In addition to the techniques learned in the "[Disassembling and Decompiling](#disassembling-and-decompiling "Disassembling and Decompiling")" section, for this section you'll need some understanding of the [Objective-C runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime "Objective-C runtime"). For instance, functions like `_objc_msgSend` or `_objc_release` are specially meaningful for the Objective-C runtime.

We will be using the [UnCrackable Level 1 crackme app](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/iOS/Level_01/UnCrackable_Level1.ipa "UnCrackable Level 1 iOS App"), which has the simple goal of finding a _secret string_ hidden somewhere in the binary. The application has a single home screen and a user can interact via inputting custom strings in the provided text field.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_app_home_screen2.png) \

When the user inputs the wrong string, the application shows a pop-up with the "Verification Failed" message.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_app_wrong_input.png) \

You can keep note of the strings displayed in the pop-up, as this might be helpful when searching for the code where the input is processed and a decision is being made. Luckily, the complexity and interaction with this application is straightforward, which bodes well for our reversing endeavors.

> For static analysis in this section, we will be using Ghidra 9.0.4. Ghidra 9.1_beta auto-analysis has a bug and does not show the Objective-C classes.

We can start by checking the strings present in the binary by opening it in Ghidra. The listed strings might be overwhelming at first, but with some experience in reversing Objective-C code, you'll learn how to _filter_ and discard the strings that are not really helpful or relevant. For instance, the ones shown in screenshot below, which are generated for the Objective-C runtime. Other strings might be helpful in some cases, such as those containing symbols (function names, class names, etc.) and we'll be using them when performing static analysis to check if some specific function is being used.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_ghidra_objc_runtime_strings.png) \

If we continue our careful analysis, we can spot the string, "Verification Failed", which is used for the pop-up when a wrong input is given. If you follow the cross-references (Xrefs) of this string, you will reach `buttonClick` function of the `ViewController` class. We will look into the `buttonClick` function later in this section. When further checking the other strings in the application, only a few of them look a likely candidate for a _hidden flag_. You can try them and verify as well.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_ghidra_strings.png) \

Moving forward, we have two paths to take. Either we can start analyzing the `buttonClick` function identified in the above step, or start analyzing the application from the various entry points. In real world situation, most times you will be taking the first path, but from a learning perspective, in this section we will take the latter path.

An iOS application calls different predefined functions provided by the iOS runtime depending on its the state within the [application life cycle](https://developer.apple.com/documentation/uikit/app_and_environment/managing_your_app_s_life_cycle "Managing Your App\'s Life Cycle"). These functions are known as the entry points of the app. For example:

- `[AppDelegate application:didFinishLaunchingWithOptions:]` is called when the application is started for the first time.
- `[AppDelegate applicationDidBecomeActive:]` is called when the application is moving from inactive to active state.

Many applications execute critical code in these sections and therefore they're normally a good starting point in order to follow the code systematically.

Once we're done with the analysis of all the functions in the `AppDelegate` class, we can conclude that there is no relevant code present. The lack of any code in the above functions raises the question - from where is the application's initialization code being called?

Luckily the current application has a small code base, and we can find another `ViewController` class in the **Symbol Tree** view. In this class, function `viewDidLoad` function looks interesting. If you check the documentation of [`viewDidLoad`](https://developer.apple.com/documentation/uikit/uiviewcontroller/1621495-viewdidload "viewDidLoad()"), you can see that it can also be used to perform additional initialization on views.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_ghidra_viewdidload_decompile.png) \

If we check the decompilation of this function, there are a few interesting things going on. For instance, there is a call to a native function at line 31 and a label is initialized with a `setHidden` flag set to 1 in lines 27-29. You can keep a note of these observations and continue exploring the other functions in this class. For brevity, exploring the other parts of the function is left as an exercise for the readers.

In our first step, we observed that the application verifies the input string only when the UI button is pressed. Thus, analyzing the `buttonClick` function is an obvious target. As earlier mentioned, this function also contains the string we see in the pop-ups. At line 29 a decision is being made, which is based on the result of `isEqualString` (output saved in `uVar1` at line 23). The input for the comparison is coming from the text input field (from the user) and the value of the `label`. Therefore, we can assume that the hidden flag is stored in that label.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_ghidra_buttonclick_decompiled.png) \

Now we have followed the complete flow and have all the information about the application flow. We also concluded that the hidden flag is present in a text label and in order to determine the value of the label, we need to revisit `viewDidLoad` function, and understand what is happening in the native function identified. Analysis of the native function is discussed in "[Reviewing Disassembled Native Code](#reviewing-disassembled-native-code "Reviewing Disassembled Native Code")".

#### Reviewing Disassembled Native Code

Analyzing disassembled native code requires a good understanding of the calling conventions and instructions used by the underlying platform. In this section we are looking in ARM64 disassembly of the native code. A good starting point to learn about ARM architecture is available at [Introduction to ARM Assembly Basics](https://azeria-labs.com/writing-arm-assembly-part-1/ "Introduction to ARM Assembly Basics") by Azeria Labs Tutorials. This is a quick summary of the things that we will be using in this section:

- In ARM64, a register is of 64 bit in size and referred to as Xn, where n is a number from 0 to 31. If the lower (LSB) 32 bits of the register are used then it's referred to as Wn.
- The input parameters to a function are passed in the X0-X7 registers.
- The return value of the function is passed via the X0 register.
- Load (LDR) and store (STR) instructions are used to read or write to memory from/to a register.
- B, BL, BLX are branch instructions used for calling a function.

As mentioned above as well, Objective-C code is also compiled to native binary code, but analyzing C/C++ native can be more challenging. In case of Objective-C there are various symbols (especially function names) present, which eases the understanding of the code. In the above section we've learned that the presence of function names like `setText`, `isEqualStrings` can help us in quickly understanding the semantics of the code. In case of C/C++ native code, if all the binaries are stripped, there can be very few or no symbols present to assist us into analyzing it.

Decompilers can help us in analyzing native code, but they should be used with caution. Modern decompilers are very sophisticated and among many techniques used by them to decompile code, a few of them are heuristics based. Heuristics based techniques might not always give correct results, one such case being, determining the number of input parameters for a given native function. Having knowledge of analyzing disassembled code, assisted with decompilers can make analyzing native code less error prone.

We will be analyzing the native function identified in `viewDidLoad` function in the previous section. The function is located at offset 0x1000080d4. The return value of this function used in the `setText` function call for the label. This text is used to compare against the user input. Thus, we can be sure that this function will be returning a string or equivalent.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_ghidra_native_disassembly.png) \

The first thing we can see in the disassembly of the function is that there is no input to the function. The registers X0-X7 are not read throughout the function. Also, there are multiple calls to other functions like the ones at 0x100008158, 0x10000dbf0 etc.

The instructions corresponding to one such function calls can be seen below. The branch instruction `bl` is used to call the function at 0x100008158.

```gnuassembler
1000080f0 1a 00 00 94     bl         FUN_100008158
1000080f4 60 02 00 39     strb       w0,[x19]=>DAT_10000dbf0
```

The return value from the function (found in W0), is stored to the address in register X19 (`strb` stores a byte to the address in register). We can see the same pattern for other function calls, the returned value is stored in X19 register and each time the offset is one more than the previous function call. This behavior can be associated with populating each index of a string array at a time. Each return value is been written to an index of this string array. There are 11 such calls, and from the current evidence we can make an intelligent guess that length of the hidden flag is 11. Towards the end of the disassembly, the function returns with the address to this string array.

```gnuassembler
100008148 e0 03 13 aa     mov        x0=>DAT_10000dbf0,x19
```

To determine the value of the hidden flag we need to know the return value of each of the subsequent function calls identified above. When analyzing the function 0x100006fb4, we can observe that this function is much bigger and more complex than the previous one we analyzed. Function graphs can be very helpful when analyzing complex functions, as it helps into better understanding the control flow of the function. Function graphs can be obtained in Ghidra by clicking the **Display function graph** icon in the sub-menu.

![Function graph from 0x100006fb4](Images/Chapters/0x06c/manual_reversing_ghidra_function_graph.png) \

Manually analyzing all the native functions completely will be time consuming and might not be the wisest approach. In such a scenario using a dynamic analysis approach is highly recommended. For instance, by using the techniques like hooking or simply debugging the application, we can easily determine the returned values. Normally it's a good idea to use a dynamic analysis approach and then fallback to manually analyzing the functions in a feedback loop. This way you can benefit from both approaches at the same time while saving time and reducing effort. Dynamic analysis techniques are discussed in "[Dynamic Analysis](#dynamic-analysis "Dynamic Analysis")" section.

### Automated Static Analysis

Several automated tools for analyzing iOS apps are available; most of them are commercial tools. The free and open source tools [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF "Mobile Security Framework (MobSF)") and [objection](https://github.com/sensepost/objection "objection") have some static and dynamic analysis functionality. Additional tools are listed in the "Static Source Code Analysis" section of the "Testing Tools" appendix.

Don't shy away from using automated scanners for your analysis - they help you pick low-hanging fruit and allow you to focus on the more interesting aspects of analysis, such as the business logic. Keep in mind that static analyzers may produce false positives and false negatives; always review the findings carefully.

## Dynamic Analysis

Life is easy with a jailbroken device: not only do you gain easy privileged access to the device, the lack of code signing allows you to use more powerful dynamic analysis techniques. On iOS, most dynamic analysis tools are based on Cydia Substrate, a framework for developing runtime patches, or Frida, a dynamic introspection tool. For basic API monitoring, you can get away with not knowing all the details of how Substrate or Frida work - you can simply use existing API monitoring tools.

### Dynamic Analysis on Non-Jailbroken Devices

#### Automated Repackaging with Objection

[Objection](https://github.com/sensepost/objection "Objection") is a mobile runtime exploration toolkit based on Frida. One of the biggest advantages about Objection is that it enables testing with non-jailbroken devices. It does this by automating the process of app repackaging with the `FridaGadget.dylib` library. A detailed explanation of the repackaging and resigning process can be found in the next chapter "Manual Repackaging".
We won't cover Objection in detail in this guide, as you can find exhaustive documentation on the official [wiki pages](https://github.com/sensepost/objection/wiki "Objection - Documentation").

#### Manual Repackaging

If you don't have access to a jailbroken device, you can patch and repackage the target app to load a dynamic library at startup. This way, you can instrument the app and do pretty much everything you need to do for a dynamic analysis (of course, you can't break out of the sandbox this way, but you won't often need to). However, this technique works only if the app binary isn't FairPlay-encrypted (i.e., obtained from the App Store).

Thanks to Apple's confusing provisioning and code-signing system, re-signing an app is more challenging than you would expect. iOS won't run an app unless you get the provisioning profile and code signature header exactly right. This requires learning many concepts-certificate types, Bundle IDs, application IDs, team identifiers, and how Apple's build tools connect them. Getting the OS to run a binary that hasn't been built via the default method (Xcode) can be a daunting process.

We'll use [optool](0x08-Testing-Tools.md#optool), Apple's build tools, and some shell commands. Our method is inspired by [Vincent Tan's Swizzler project](https://github.com/vtky/Swizzler2/ "Swizzler"). [The NCC group](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "NCC blog - iOS instrumentation without jailbreak") has described an alternative repackaging method.

To reproduce the steps listed below, download [UnCrackable iOS App Level 1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/iOS/Level_01 "Crackmes - iOS Level 1") from the OWASP Mobile Testing Guide repository. Our goal is to make the UnCrackable app load `FridaGadget.dylib` during startup so we can instrument the app with Frida.

> Please note that the following steps apply to macOS only, as Xcode is only available for macOS.

#### Getting a Developer Provisioning Profile and Certificate

The *provisioning profile* is a plist file signed by Apple, which adds your code-signing certificate to its list of accepted certificates on one or more devices. In other words, this represents Apple explicitly allowing your app to run for certain reasons, such as debugging on selected devices (development profile). The provisioning profile also includes the *entitlements* granted to your app. The *certificate* contains the private key you'll use to sign.

Depending on whether you're registered as an iOS developer, you can obtain a certificate and provisioning profile in one of the following ways:

**With an iOS developer account:**

If you've developed and deployed iOS apps with Xcode before, you already have your own code-signing certificate installed. Use the *security* tool to list your signing identities:

```bash
$ security find-identity -v
 1) 61FA3547E0AF42A11E233F6A2B255E6B6AF262CE "iPhone Distribution: Company Name Ltd."
 2) 8004380F331DCA22CC1B47FB1A805890AE41C938 "iPhone Developer: Bernhard Müller (RV852WND79)"
```

Log into the Apple Developer portal to issue a new App ID, then issue and download the profile. An App ID is a two-part string: a Team ID supplied by Apple and a bundle ID search string that you can set to an arbitrary value, such as `com.example.myapp`. Note that you can use a single App ID to re-sign multiple apps. Make sure you create a *development* profile and not a *distribution* profile so that you can debug the app.

In the examples below, I use my signing identity, which is associated with my company's development team. I created the App ID "sg.vp.repackaged" and the provisioning profile "AwesomeRepackaging" for these examples. I ended up with the file `AwesomeRepackaging.mobileprovision`-replace this with your own filename in the shell commands below.

**With a Regular Apple ID:**

Apple will issue a free development provisioning profile even if you're not a paying developer. You can obtain the profile via Xcode and your regular Apple account: simply create an empty iOS project and extract `embedded.mobileprovision` from the app container, which is in the Xcode subdirectory of your home directory: `~/Library/Developer/Xcode/DerivedData/<ProjectName>/Build/Products/Debug-iphoneos/<ProjectName>.app/`. The [NCC blog post "iOS instrumentation without jailbreak"](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/ "iOS instrumentation without jailbreak") explains this process in great detail.

Once you've obtained the provisioning profile, you can check its contents with the *security* tool. You'll find the entitlements granted to the app in the profile, along with the allowed certificates and devices. You'll need these for code-signing, so extract them to a separate plist file as shown below. Have a look at the file contents to make sure everything is as expected.

```bash
$ security cms -D -i AwesomeRepackaging.mobileprovision > profile.plist
$ /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist
$ cat entitlements.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>application-identifier</key>
 <string>LRUD9L355Y.sg.vantagepoint.repackage</string>
 <key>com.apple.developer.team-identifier</key>
 <string>LRUD9L355Y</string>
 <key>get-task-allow</key>
 <true/>
 <key>keychain-access-groups</key>
 <array>
   <string>LRUD9L355Y.*</string>
 </array>
</dict>
</plist>
```

Note the application identifier, which is a combination of the Team ID (LRUD9L355Y) and Bundle ID (sg.vantagepoint.repackage). This provisioning profile is only valid for the app that has this App ID. The `get-task-allow` key is also important: when set to `true`, other processes, such as the debugging server, are allowed to attach to the app (consequently, this would be set to `false` in a distribution profile).

### Basic Information Gathering

On iOS, collecting basic information about a running process or an application can be slightly more challenging than compared to Android. On Android (or any Linux-based OS), process information is exposed as readable text files via *procfs*. Thus, any information about a target process can be obtained on a rooted device by parsing these text files. In contrast, on iOS there is no procfs equivalent present. Also, on iOS many standard UNIX command line tools for exploring process information, for instance lsof and vmmap, are removed to reduce the firmware size.

In this section, we will learn how to collect process information on iOS using command line tools like lsof. Since many of these tools are not present on iOS by default, we need to install them via alternative methods. For instance, lsof can be installed using [Cydia](0x08-Testing-Tools.md#cydia) (the executable is not the latest version available, but nevertheless addresses our purpose).

#### Open Files

`lsof` is a powerful command, and provides a plethora of information about a running process. It can provide a list of all open files, including a stream, a network file or a regular file. When invoking the `lsof` command without any option it will list all open files belonging to all active processes on the system, while when invoking with the flags `-c <process name>` or `-p <pid>`, it returns the list of open files for the specified process. The [man page](http://man7.org/linux/man-pages/man8/lsof.8.html "Man Page of lsof") shows various other options in detail.

Using `lsof` for an iOS application running with PID 2828, list various open files as shown below.

```bash
iPhone:~ root# lsof -p 2828
COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
iOweApp 2828 mobile  cwd    DIR    1,2      864      2 /
iOweApp 2828 mobile  txt    REG    1,3   206144 189774 /private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp
iOweApp 2828 mobile  txt    REG    1,3     5492 213230 /private/var/mobile/Containers/Data/Application/5AB3E437-9E2D-4F04-BD2B-972F6055699E/tmp/com.apple.dyld/iOweApp-6346DC276FE6865055F1194368EC73CC72E4C5224537F7F23DF19314CF6FD8AA.closure
iOweApp 2828 mobile  txt    REG    1,3    30628 212198 /private/var/preferences/Logging/.plist-cache.vqXhr1EE
iOweApp 2828 mobile  txt    REG    1,2    50080 234433 /usr/lib/libobjc-trampolines.dylib
iOweApp 2828 mobile  txt    REG    1,2   344204  74185 /System/Library/Fonts/AppFonts/ChalkboardSE.ttc
iOweApp 2828 mobile  txt    REG    1,2   664848 234595 /usr/lib/dyld
...
```

#### Loaded Native Libraries

You can use the `list_frameworks` command in [objection](0x08-Testing-Tools.md#objection) to list all the application's bundles that represent Frameworks.

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios bundles list_frameworks
Executable      Bundle                                     Version    Path
--------------  -----------------------------------------  ---------  -------------------------------------------
Bolts           org.cocoapods.Bolts                        1.9.0      ...8/DVIA-v2.app/Frameworks/Bolts.framework
RealmSwift      org.cocoapods.RealmSwift                   4.1.1      ...A-v2.app/Frameworks/RealmSwift.framework
                                                                      ...ystem/Library/Frameworks/IOKit.framework
...

#### Open Connections

`lsof` command when invoked with option `-i`, it gives the list of open network ports for all active processes on the device. To get a list of open network ports for a specific process, the `lsof -i -a -p <pid>` command can be used, where `-a` (AND) option is used for filtering. Below a filtered output for PID 1 is shown.

```bash
iPhone:~ root# lsof -i -a -p 1
COMMAND PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd   1 root   27u  IPv6 0x69c2ce210efdc023      0t0  TCP *:ssh (LISTEN)
launchd   1 root   28u  IPv6 0x69c2ce210efdc023      0t0  TCP *:ssh (LISTEN)
launchd   1 root   29u  IPv4 0x69c2ce210eeaef53      0t0  TCP *:ssh (LISTEN)
launchd   1 root   30u  IPv4 0x69c2ce210eeaef53      0t0  TCP *:ssh (LISTEN)
launchd   1 root   31u  IPv4 0x69c2ce211253b90b      0t0  TCP 192.168.1.12:ssh->192.168.1.8:62684 (ESTABLISHED)
launchd   1 root   42u  IPv4 0x69c2ce211253b90b      0t0  TCP 192.168.1.12:ssh->192.168.1.8:62684 (ESTABLISHED)
```

#### Sandbox Inspection

On iOS, each application gets a sandboxed folder to store its data. As per the iOS security model, an application's sandboxed folder cannot be accessed by another application. Additionally, the users do not have direct access to the iOS filesystem, thus preventing browsing or extraction of data from the filesystem. In iOS < 8.3 there were applications available which can be used to browse the device's filesystem, such as iExplorer and iFunBox, but in the recent version of iOS (>8.3) the sandboxing rules are more stringent and these applications do not work anymore. As a result, if you need to access the filesystem it can only be accessed on a jailbroken device. As part of the jailbreaking process, the application sandbox protection is disabled and thus enabling an easy access to sandboxed folders.

The contents of an application's sandboxed folder has already been discussed in "[Accessing App Data Directories](0x06b-Basic-Security-Testing.md#accessing-app-data-directories)" in the chapter iOS Basic Security Testing. This chapter gives an overview of the folder structure and which directories you should analyze.

### Debugging

Coming from a Linux background you'd expect the `ptrace` system call to be as powerful as you're used to but, for some reason, Apple decided to leave it incomplete. iOS debuggers such as LLDB use it for attaching, stepping or continuing the process but they cannot use it to read or write memory (all `PT_READ_*` and `PT_WRITE*` requests are missing). Instead, they have to obtain a so-called Mach task port (by calling `task_for_pid` with the target process ID) and then use the Mach IPC interface API functions to perform actions such as suspending the target process and reading/writing register states (`thread_get_state`/`thread_set_state`) and virtual memory (`mach_vm_read`/`mach_vm_write`).

> For more information you can refer to the LLVM project in GitHub which contains the [source code for LLDB](https://github.com/llvm/llvm-project/tree/main/lldb "LLDB") as well as Chapter 5 and 13 from "Mac OS X and iOS Internals: To the Apple's Core" [#levin] and Chapter 4 "Tracing and Debugging" from "The Mac Hacker's Handbook" [#miller].

#### Debugging with LLDB

The default debugserver executable that Xcode installs can't be used to attach to arbitrary processes (it is usually used only for debugging self-developed apps deployed with Xcode). To enable debugging of third-party apps, the `task_for_pid-allow` entitlement must be added to the debugserver executable so that the debugger process can call `task_for_pid` to obtain the target Mach task port as seen before. An easy way to do this is to add the entitlement to the [debugserver binary shipped with Xcode](http://iphonedevwiki.net/index.php/Debugserver "Debug Server on the iPhone Dev Wiki").

To obtain the executable, mount the following DMG image:

```bash
/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/<target-iOS-version>/DeveloperDiskImage.dmg
```

You'll find the debugserver executable in the `/usr/bin/` directory on the mounted volume. Copy it to a temporary directory, then create a file called `entitlements.plist` with the following content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.springboard.debugapplications</key>
    <true/>
    <key>run-unsigned-code</key>
    <true/>
    <key>get-task-allow</key>
    <true/>
    <key>task_for_pid-allow</key>
    <true/>
</dict>
</plist>
```

Apply the entitlement with codesign:

```bash
$ codesign -s - --entitlements entitlements.plist -f debugserver
```

Copy the modified binary to any directory on the test device. The following examples use usbmuxd to forward a local port through USB.

```bash
$ iproxy 2222 22
$ scp -P 2222 debugserver root@localhost:/tmp/
```

Note: On iOS 12 and higher, use the following procedure to sign the debugserver binary obtained from the XCode image.

1) Copy the debugserver binary to the device via scp, for example, in the /tmp folder.

2) Connect to the device via SSH and create the file, named entitlements.xml, with the following content:

    ```xml
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>platform-application</key>
        <true/>
        <key>com.apple.private.security.no-container</key>
        <true/>
        <key>com.apple.private.skip-library-validation</key>
        <true/>
        <key>com.apple.backboardd.debugapplications</key>
        <true/>
        <key>com.apple.backboardd.launchapplications</key>
        <true/>
        <key>com.apple.diagnosticd.diagnostic</key>
        <true/>
        <key>com.apple.frontboard.debugapplications</key>
        <true/>
        <key>com.apple.frontboard.launchapplications</key>
        <true/>
        <key>com.apple.security.network.client</key>
        <true/>
        <key>com.apple.security.network.server</key>
        <true/>
        <key>com.apple.springboard.debugapplications</key>
        <true/>
        <key>com.apple.system-task-ports</key>
        <true/>
        <key>get-task-allow</key>
        <true/>
        <key>run-unsigned-code</key>
        <true/>
        <key>task_for_pid-allow</key>
        <true/>
    </dict>
    </plist>
    ```

3) Type the following command to sign the debugserver binary:

    ```bash
    $ ldid -Sentitlements.xml debugserver
    ```

4) Verify that the debugserver binary can be executed via the following command:

    ```bash
    $ ./debugserver
    ```

You can now attach debugserver to any process running on the device.

```bash
VP-iPhone-18:/tmp root# ./debugserver *:1234 -a 2670
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-320.2.89
for armv7.
Attaching to process 2670...
```

With the following command you can launch an application via debugserver running on the target device:

```bash
debugserver -x backboard *:1234 /Applications/MobileSMS.app/MobileSMS
```

Attach to an already running application:

```bash
debugserver *:1234 -a "MobileSMS"
```

You may connect now to the iOS device from your host computer:

```bash
(lldb) process connect connect://<ip-of-ios-device>:1234
```

Typing `image list` gives a list of main executable and all dependent libraries.

#### Debugging Release Apps

In the previous section we learned about how to setup a debugging environment on an iOS device using LLDB. In this section we will use this information and learn how to debug a 3rd party release application. We will continue using the [UnCrackable Level 1 crackme app](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/iOS/Level_01/UnCrackable_Level1.ipa "UnCrackable Level 1 iOS App") and solve it using a debugger.

In contrast to a debug build, the code compiled for a release build is optimized to achieve maximum performance and minimum binary build size. As a general best practice, most of the debug symbols are stripped for a release build, adding a layer of complexity when reverse engineering and debugging the binaries.

Due to the absence of the debug symbols, symbol names are missing from the backtrace outputs and setting breakpoints by simply using function names is not possible. Fortunately, debuggers also support setting breakpoints directly on memory addresses. Further in this section we will learn how to do so and eventually solve the crackme challenge.

Some groundwork is needed before setting a breakpoint using memory addresses. It requires determining two offsets:

1. Breakpoint offset: The _address offset_ of the code where we want to set a breakpoint. This address is obtained by performing static analysis of the code in a disassembler like Ghidra.
2. ASLR shift offset: The _ASLR shift offset_ for the current process. Since ASLR offset is randomly generated on every new instance of an application, this has to be obtained for every debugging session individually. This is determined using the debugger itself.

> iOS is a modern operating system with multiple techniques implemented to mitigate code execution attacks, one such technique being Address Space Randomization Layout (ASLR). On every new execution of an application, a random ASLR shift offset is generated, and various process' data structures are shifted by this offset.

The final breakpoint address to be used in the debugger is the sum of the above two addresses (Breakpoint offset + ASLR shift offset). This approach assumes that the image base address (discussed shortly) used by the disassembler and iOS is the same, which is true most of the time.

When a binary is opened in a disassembler like Ghidra, it loads a binary by emulating the respective operating system's loader. The address at which the binary is loaded is called _image base address_. All the code and symbols inside this binary can be addressed using a constant address offset from this image base address. In Ghidra, the image base address can be obtained by determining the address of the start of a Mach-O file. In this case, it is 0x100000000.

![Obtaining image base address using Ghidra](Images/Chapters/0x06c/debugging_ghidra_image_base_address.png "Obtaining image base address using Ghidra") \

From our previous analysis of the UnCrackable Level 1 application in "[Manual (Reversed) Code Review](#manual-reversed-code-review)" section, the value of the hidden string is stored in a label with the `hidden` flag set. In the disassembly, the text value of this label is stored in register `X21`, stored via `mov` from `X0`, at offset 0x100004520. This is our _breakpoint offset_.

![Breakpoint address using Ghidra](Images/Chapters/0x06c/debugging_ghidra_breakpoint.png "Breakpoint address using Ghidra") \

For the second address, we need to determine the _ASLR shift offset_ for a given process. The ASLR offset can be determined by using the LLDB command `image list -o -f`. The output is shown in the screenshot below.

![Process image list](Images/Chapters/0x06c/debugging_lldb_image_list.png "Process image list") \

In the output, the first column contains the sequence number of the image ([X]), the second column contains the randomly generated ASLR offset, while 3rd column contains the full path of the image and towards the end, content in the bracket shows the image base address after adding ASLR offset to the original image base address (0x100000000 + 0x70000 = 0x100070000). You will notice the image base address of 0x100000000 is same as in Ghidra. Now, to obtain the effective memory address for a code location we only need to add ASLR offset to the address identified in Ghidra. The effective address to set the breakpoint will be 0x100004520 + 0x70000 = 0x100074520. The breakpoint can be set using command `b 0x100074520`.

> In the above output, you may also notice that many of the paths listed as images do not point to the file system on the iOS device. Instead, they point to a certain location on the host computer on which LLDB is running. These images are system libraries for which debug symbols are available on the host computer to aid in application development and debugging (as part of the Xcode iOS SDK). Therefore, you may set breakpoints to these libraries directly by using function names.

After putting the breakpoint and running the app, the execution will be halted once the breakpoint is hit. Now you can access and explore the current state of the process. In this case, you know from the previous static analysis that the register `X0` contains the hidden string, thus let's explore it. In LLDB you can print Objective-C objects using the `po` (_print object_) command.

![Setting breakpoint in LLDB](Images/Chapters/0x06c/debugging_lldb_breakpoint_solution.png "Setting breakpoint in LLDB") \

Voila, the crackme can be easily solved aided by static analysis and a debugger. There are plethora of features implemented in LLDB, including changing the value of the registers, changing values in the process memory and even [automating tasks using Python scripts](https://lldb.llvm.org/use/python.html "LLDB - Python Scripting").

Officially Apple recommends use of LLDB for debugging purposes, but GDB can be also used on iOS. The techniques discussed above are applicable while debugging using GDB as well, provided the LLDB specific commands are [changed to GDB commands](https://lldb.llvm.org/use/map.html "GDB to LLDB command map").

### Tracing

Tracing involves recording the information about a program's execution. In contrast to Android, there are limited options available for tracing various aspects of an iOS app. In this section we will be heavily relying on tools such as Frida for performing tracing.

#### Method Tracing

Intercepting Objective-C methods is a useful iOS security testing technique. For example, you may be interested in data storage operations or network requests. In the following example, we'll write a simple tracer for logging HTTP(S) requests made via iOS standard HTTP APIs. We'll also show you how to inject the tracer into the Safari web browser.

In the following examples, we'll assume that you are working on a jailbroken device. If that's not the case, you first need to follow the steps outlined in section [Repackaging and Re-Signing](#repackaging-and-re-signing "Repackaging and Re-Signing") to repackage the Safari app.

Frida comes with `frida-trace`, a function tracing tool. `frida-trace` accepts Objective-C methods via the `-m` flag. You can pass it wildcards as well-given `-[NSURL *]`, for example, `frida-trace` will automatically install hooks on all `NSURL` class selectors. We'll use this to get a rough idea about which library functions Safari calls when the user opens a URL.

Run Safari on the device and make sure the device is connected via USB. Then start `frida-trace` as follows:

```bash
$ frida-trace -U -m "-[NSURL *]" Safari
Instrumenting functions...
-[NSURL isMusicStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isMusicStoreURL_.js"
-[NSURL isAppStoreURL]: Loaded handler at "/Users/berndt/Desktop/__handlers__/__NSURL_isAppStoreURL_.js"
(...)
Started tracing 248 functions. Press Ctrl+C to stop.
```

Next, navigate to a new website in Safari. You should see traced function calls on the `frida-trace` console. Note that the `initWithURL:` method is called to initialize a new URL request object.

```bash
           /* TID 0xc07 */
  20313 ms  -[NSURLRequest _initWithCFURLRequest:0x1043bca30 ]
 20313 ms  -[NSURLRequest URL]
(...)
 21324 ms  -[NSURLRequest initWithURL:0x106388b00 ]
 21324 ms     | -[NSURLRequest initWithURL:0x106388b00 cachePolicy:0x0 timeoutInterval:0x106388b80
```

#### Native Libraries Tracing

As discussed earlier in this chapter, iOS applications can also contain native code (C/C++ code) and it can be traced using the `frida-trace` CLI as well. For example, you can trace calls to the `open` function by running the following command:

```bash
$ frida-trace -U -i "open" sg.vp.UnCrackable1
```

The overall approach and further improvisation for tracing native code using Frida is similar to the one discussed in the Android "[Tracing](0x05c-Reverse-Engineering-and-Tampering.md#tracing "Tracing")" section.

Unfortunately, there are no tools such as `strace` or `ftrace` available to trace syscalls or function calls of an iOS app. Only `DTrace` exists, which is a very powerful and versatile tracing tool, but it's only available for MacOS and not for iOS.

### Emulation-based Analysis

#### iOS Simulator

Apple provides a simulator app within Xcode which provides a _real iOS device looking_ user interface for iPhone, iPad or Apple Watch. It allows you to rapidly prototype and test debug builds of your applications during the development process, but actually **it is not an emulator**. Difference between a simulator and an emulator is previously discussed in "[Emulation-based Dynamic Analysis](0x04c-Tampering-and-Reverse-Engineering.md#emulation-based-dynamic-analysis "Emulation-based Dynamic Analysis")" section.

While developing and debugging an application, the Xcode toolchain generates x86 code, which can be executed in the iOS simulator. However, for a release build, only ARM code is generated (incompatible with the iOS simulator). That's why applications downloaded from the Apple App Store cannot be used for any kind of application analysis on the iOS simulator.

#### Corellium

Corellium is a commercial tool which offers virtual iOS devices running actual iOS firmware, being the only publicly available iOS emulator ever. Since it is a proprietary product, not much information is available about the implementation. Corellium has no trial or community licenses available, therefore we won't go into much detail regarding its use.

Corellium allows you to launch multiple instances of a device (jailbroken or not) which are accessible as local devices (with a simple VPN configuration). It has the ability to take and restore snapshots of the device state, and also offers a convenient web-based shell to the device. Finally and most importantly, due to its "emulator" nature, you can execute applications downloaded from the Apple App Store, enabling any kind of application analysis as you know it from real iOS (jailbroken) devices.

## Binary Analysis

An introduction to binary analysis using binary analysis frameworks has already been discussed in the "[Dynamic Analysis](0x05c-Reverse-Engineering-and-Tampering.md#dynamic-analysis "Dynamic analysis")" section for Android. We recommend you to revisit this section and refresh the concepts on this subject.

For Android, we used Angr's symbolic execution engine to solve a challenge. In this section, we will firstly use Unicorn to solve [UnCrackable Level 1 crackme app](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/iOS/Level_01/UnCrackable_Level1.ipa "UnCrackable Level 1 iOS App") challenge and then we will revisit the Angr binary analysis framework to analyze the challenge but instead of symbolic execution we will use its concrete execution (or dynamic execution) features.

### Unicorn

[Unicorn](http://www.unicorn-engine.org/ "Unicorn") is a lightweight, multi-architecture CPU emulator framework based on [QEMU](https://www.qemu.org/ "QEMU") and [goes beyond it](https://www.unicorn-engine.org/docs/beyond_qemu.html "Beyond QEMU") by adding useful features especially made for CPU emulation. Unicorn provides the basic infrastructure needed to execute processor instructions. In this section we will use [Unicorn's Python bindings](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python "Unicorn Python bindings") to solve the [UnCrackable App for iOS Level 1](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/iOS/Level_01 "UnCrackable App for iOS Level 1").

To use Unicorn's _full power_, we would need to implement all the necessary infrastructure which generally is readily available from the operating system, e.g. binary loader, linker and other dependencies or use another higher level frameworks such as [Qiling](https://qiling.io "Qiling") which leverages Unicorn to emulate CPU instructions, but understands the OS context. However, this is superfluous for this very localized challenge where only executing a small part of the binary will suffice.

While performing manual analysis in "[Reviewing Disassembled Native Code](#reviewing-disassembled-native-code "Reviewing Disassembled Native Code")" section, we determined that the function at address 0x1000080d4 is responsible for dynamically generating the secret string. As we're about to see, all the necessary code is pretty much self-contained in the binary, making this a perfect scenario to use a CPU emulator like Unicorn.

![OWASP MSTG](Images/Chapters/0x06c/manual_reversing_ghidra_native_disassembly.png) \

If we analyze that function and the subsequent function calls, we will observe that there is no hard dependency on any external library and neither it's performing any system calls. The only access external to the functions occurs for instance at address 0x1000080f4, where a value is being stored to address 0x10000dbf0, which maps to the `__data` section.

Therefore, in order to correctly emulate this section of the code, apart from the `__text` section (which contains the instructions) we also need to load the `__data` section.

To solve the challenge using Unicorn we will perform the following steps:

- Get the ARM64 version of the binary by running `lipo -thin arm64 <app_binary> -output uncrackable.arm64` (ARMv7 can be used as well).
- Extract the `__text` and `__data` section from the binary.
- Create and map the memory to be used as stack memory.
- Create memory and load the `__text` and `__data` section.
- Execute the binary by providing the start and end address.
- Finally, dump the return value from the function, which in this case is our secret string.

To extract the content of `__text` and `__data` section from the Mach-O binary we will use [LIEF](https://lief.quarkslab.com/ "Lief"), which provides a convenient abstraction to manipulate multiple executable file formats. Before loading these sections to memory, we need to determine their base addresses, e.g. by using Ghidra, Radare2 or IDA Pro.

<img src="Images/Chapters/0x06c/uncrackable_sections.png" width="500px"/>

From the above table, we will use the base address 0x10000432c for `__text` and 0x10000d3e8 for `__data` section to load them at in the memory.

> While allocating memory for Unicorn, the memory addresses should be 4k page aligned and also the allocated size should be a multiple of 1024.

The following script emulates the function at 0x1000080d4 and dumps the secret string:

```python

import lief
from unicorn import *
from unicorn.arm64_const import *

# --- Extract __text and __data section content from the binary ---
binary = lief.parse("uncrackable.arm64")
text_section = binary.get_section("__text")
text_content = text_section.content

data_section = binary.get_section("__data")
data_content = data_section.content

# --- Setup Unicorn for ARM64 execution ---
arch = "arm64le"
emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

# --- Create Stack memory ---
addr = 0x40000000
size = 1024*1024
emu.mem_map(addr, size)
emu.reg_write(UC_ARM64_REG_SP, addr + size - 1)

# --- Load text section --
base_addr = 0x100000000
tmp_len = 1024*1024
text_section_load_addr = 0x10000432c
emu.mem_map(base_addr, tmp_len)
emu.mem_write(text_section_load_addr, bytes(text_content))

# --- Load data section ---
data_section_load_addr = 0x10000d3e8
emu.mem_write(data_section_load_addr, bytes(data_content))

# --- Hack for stack_chk_guard ---
# without this will throw invalid memory read at 0x0
emu.mem_map(0x0, 1024)
emu.mem_write(0x0, b"00")


# --- Execute from 0x1000080d4 to 0x100008154 ---
emu.emu_start(0x1000080d4, 0x100008154)
ret_value = emu.reg_read(UC_ARM64_REG_X0)

# --- Dump return value ---
print(emu.mem_read(ret_value, 11))
```

> You may notice that there is an additional memory allocation at address 0x0, this is a simple hack around `stack_chk_guard` check. Without this, there will be a invalid memory read error and binary cannot be executed. With this hack, the program will access the value at 0x0 and use it for the `stack_chk_guard` check.

To summarize, using Unicorn do require some additional setup before executing the binary, but once done, this tool can help to provide deep insights into the binary. It provides the flexibility to execute the full binary or a limited part of it. Unicorn also exposes APIs to attach hooks to the execution. Using these hooks you can observe the state of the program at any point during the execution or even manipulate the register or variable values and forcefully explore other execution branches in a program. Another advantage when running a binary in Unicorn is that you don't need to worry about various checks like root/jailbreak detection or debugger detection etc.

### Angr

[Angr](0x08-Testing-Tools.md#angr) is a very versatile tool, providing multiple techniques to facilitate binary analysis, while supporting various file formats and hardware instructions sets.

> The Mach-O backend in Angr is not well-supported, but it works perfectly fine for our case.

While manually analyzing the code in the [Reviewing Disassembled Native Code](#reviewing-disassembled-native-code "Reviewing Disassembled Native Code")" section, we reached a point where performing further manual analysis was cumbersome. The function at offset `0x1000080d4` was identified as the final target which contains the secret string.

If we revisit that function, we can see that it involves multiple sub-function calls and interestingly none of these functions have any dependencies on other library calls or system calls. This is a perfect case to use Angr's concrete execution engine. Follow the steps below to solve this challenge:

- Get the ARM64 version of the binary by running `lipo -thin arm64 <app_binary> -output uncrackable.arm64` (ARMv7 can be used as well).
- Create an Angr `Project` by loading the above binary.
- Get a `callable` object by passing the address of the function to be executed. From the Angr documentation: "A Callable is a representation of a function in the binary that can be interacted with like a native python function.".
- Pass the above `callable` object to the concrete execution engine, which in this case is `claripy.backends.concrete`.
- Access the memory and extract the string from the pointer returned by the above function.

```python
import angr
import claripy

def solve():

    # Load the binary by creating angr project.
    project = angr.Project('uncrackable.arm64')

    # Pass the address of the function to the callable
    func = project.factory.callable(0x1000080d4)

    # Get the return value of the function
    ptr_secret_string = claripy.backends.concrete.convert(func()).value
    print("Address of the pointer to the secret string: " + hex(ptr_secret_string))

    # Extract the value from the pointer to the secret string
    secret_string = func.result_state.mem[ptr_secret_string].string.concrete
    print(f"Secret String: {secret_string}")

solve()
```

Above, Angr executed an ARM64 code in an execution environment provided by one of its concrete execution engines. The result is accessed from the memory as if the program is executed on a real device. This case is a good example where binary analysis frameworks enable us to perform a comprehensive analysis of a binary, even in the absence of specialized devices needed to run it.

## Tampering and Runtime Instrumentation

### Patching, Repackaging, and Re-Signing

Time to get serious! As you already know, IPA files are actually ZIP archives, so you can use any ZIP tool to unpack the archive.

```bash
$ unzip UnCrackable_Level1.ipa
```

#### Patching Example: Installing Frida Gadget

IF you want to use Frida on non-jailbroken devices you'll need to include `FridaGadget.dylib`. Download it first:

```bash
$ curl -O https://build.frida.re/frida/ios/lib/FridaGadget.dylib
```

Copy `FridaGadget.dylib` into the app directory and use [optool](0x08-Testing-Tools.md#optool) to add a load command to the "UnCrackable Level 1" binary.

```bash
$ unzip UnCrackable_Level1.ipa
$ cp FridaGadget.dylib Payload/UnCrackable\ Level\ 1.app/
$ optool install -c load -p "@executable_path/FridaGadget.dylib"  -t Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Found FAT Header
Found thin header...
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm
Successfully inserted a LC_LOAD_DYLIB command for arm
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to Payload/UnCrackable Level 1.app/UnCrackable Level 1...
```

#### Patching Example: Making an App Debuggable

By default, an app available on the Apple App Store is not debuggable. In order to debug an iOS application, it must have the `get-task-allow` entitlement enabled. This entitlement allows other processes (like a debugger) to attach to the app. Xcode is not adding the `get-task-allow` entitlement in a distribution provisioning profile; it is only whitelisted and added in a development provisioning profile.

Thus, to debug an iOS application obtained from the App Store, it needs to be re-signed with a development provisioning profile with the `get-task-allow` entitlement. How to re-sign an application is discussed in the next section.

#### Repackaging and Re-Signing

Of course, tampering an app invalidates the main executable's code signature, so this won't run on a non-jailbroken device. You'll need to replace the provisioning profile and sign both the main executable and the files you've made include (e.g. `FridaGadget.dylib`) with the certificate listed in the profile.

First, let's add our own provisioning profile to the package:

```bash
$ cp AwesomeRepackaging.mobileprovision Payload/UnCrackable\ Level\ 1.app/embedded.mobileprovision
```

Next, we need to make sure that the Bundle ID in `Info.plist` matches the one specified in the profile because the codesign tool will read the Bundle ID from `Info.plist` during signing; the wrong value will lead to an invalid signature.

```bash
$ /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier sg.vantagepoint.repackage" Payload/UnCrackable\ Level\ 1.app/Info.plist
```

Finally, we use the codesign tool to re-sign both binaries. You need to use *your* signing identity (in this example 8004380F331DCA22CC1B47FB1A805890AE41C938), which you can output by executing the command `security find-identity -v`.

```bash
$ rm -rf Payload/UnCrackable\ Level\ 1.app/_CodeSignature
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938  Payload/UnCrackable\ Level\ 1.app/FridaGadget.dylib
Payload/UnCrackable Level 1.app/FridaGadget.dylib: replacing existing signature
```

`entitlements.plist` is the file you created for your empty iOS project.

```bash
$ /usr/bin/codesign --force --sign 8004380F331DCA22CC1B47FB1A805890AE41C938 --entitlements entitlements.plist Payload/UnCrackable\ Level\ 1.app/UnCrackable\ Level\ 1
Payload/UnCrackable Level 1.app/UnCrackable Level 1: replacing existing signature
```

Now you should be ready to run the modified app. Deploy and run the app on the device using [ios-deploy](0x08-Testing-Tools.md#ios-deploy):

```bash
$ ios-deploy --debug --bundle Payload/UnCrackable\ Level\ 1.app/
```

If everything went well, the app should start in debugging mode with LLDB attached. Frida should then be able to attach to the app as well. You can verify this via the frida-ps command:

```bash
$ frida-ps -U
PID  Name
---  ------
499  Gadget
```

![Frida on non-JB device](Images/Chapters/0x06b/fridaStockiOS.png "Frida on non-JB device") \

When something goes wrong (and it usually does), mismatches between the provisioning profile and code-signing header are the most likely causes. Reading the [official documentation](https://developer.apple.com/support/code-signing/ "Code Signing") helps you understand the code-signing process. Apple's [entitlement troubleshooting page](https://developer.apple.com/library/content/technotes/tn2415/_index.html "Entitlements Troubleshooting") is also a useful resource.

#### Patching React Native applications

If the [React Native](https://facebook.github.io/react-native "React Native") framework has been used for development, the main application code is in the file `Payload/[APP].app/main.jsbundle`. This file contains the JavaScript code. Most of the time, the JavaScript code in this file is minified. With the tool [JStillery](https://mindedsecurity.github.io/jstillery "JStillery"), a human-readable version of the file can be retried, which will allow code analysis. The [CLI version of JStillery](https://github.com/mindedsecurity/jstillery/ "CLI version of JStillery") and the local server are preferable to the online version because the latter discloses the source code to a third party.

At installation time, the application archive is unpacked into the folder `/private/var/containers/Bundle/Application/[GUID]/[APP].app` from iOS 10 onward, so the main JavaScript application file can be modified at this location.

To identify the exact location of the application folder, you can use the tool [ipainstaller](https://cydia.saurik.com/package/com.slugrail.ipainstaller/ "ipainstaller"):

1. Use the command `ipainstaller -l` to list the applications installed on the device. Get the name of the target application from the output list.
2. Use the command `ipainstaller -i [APP_NAME]` to display information about the target application, including the installation and data folder locations.
3. Take the path referenced at the line that starts with `Application:`.

Use the following approach to patch the JavaScript file:

1. Navigate to the application folder.
2. Copy the contents of the file `Payload/[APP].app/main.jsbundle` to a temporary file.
3. Use `JStillery` to beautify and de-obfuscate the contents of the temporary file.
4. Identify the code in the temporary file that should be patched and patch it.
5. Put the *patched code* on a single line and copy it into the original `Payload/[APP].app/main.jsbundle` file.
6. Close and restart the application.

### Dynamic Instrumentation

#### Information Gathering

In this section we will learn how to use Frida to obtain information about a running application.

#### Getting Loaded Classes and their Methods

In the Frida REPL Objective-C runtime the `ObjC` command can be used to access information within the running app. Within the `ObjC` command the function `enumerateLoadedClasses` lists the loaded classes for a given application.

```bash
$ frida -U -f com.iOweApp

[iPhone::com.iOweApp]-> ObjC.enumerateLoadedClasses()
{
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": [
        "__NSBlockVariable__",
        "__NSGlobalBlock__",
        "__NSFinalizingBlock__",
        "__NSAutoBlock__",
        "__NSMallocBlock__",
        "__NSStackBlock__"
    ],
    "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp": [
        "JailbreakDetection",
        "CriticalLogic",
        "ViewController",
        "AppDelegate"
    ]
}

```

Using `ObjC.classes.<classname>.$ownMethods` the methods declared in each class can be listed.

```bash
[iPhone::com.iOweApp]-> ObjC.classes.JailbreakDetection.$ownMethods
[
    "+ isJailbroken"
]

[iPhone::com.iOweApp]-> ObjC.classes.CriticalLogic.$ownMethods
[
    "+ doSha256:",
    "- a:",
    "- AES128Operation:data:key:iv:",
    "- coreLogic",
    "- bat",
    "- b:",
    "- hexString:"
]
```

#### Getting Loaded Libraries

In Frida REPL process related information can be obtained using the `Process` command. Within the `Process` command the function `enumerateModules` lists the libraries loaded into the process memory.

```bash
[iPhone::com.iOweApp]-> Process.enumerateModules()
[
    {
        "base": "0x10008c000",
        "name": "iOweApp",
        "path": "/private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp",
        "size": 49152
    },
    {
        "base": "0x1a1c82000",
        "name": "Foundation",
        "path": "/System/Library/Frameworks/Foundation.framework/Foundation",
        "size": 2859008
    },
    {
        "base": "0x1a16f4000",
        "name": "libobjc.A.dylib",
        "path": "/usr/lib/libobjc.A.dylib",
        "size": 200704
    },

    ...
```

Similarly, information related to various threads can be obtained.

```bash
Process.enumerateThreads()
[
    {
        "context": {
            ...
       },
        "id": 1287,
        "state": "waiting"
    },

    ...
```

The `Process` command exposes multiple functions which can be explored as per needs. Some useful functions are `findModuleByAddress`, `findModuleByName` and `enumerateRanges` besides others.

#### Method Hooking

##### Frida

In section ["Execution Tracing"](#execution-tracing "Execution Tracing") we've used frida-trace when navigating to a website in Safari and found that the `initWithURL:` method is called to initialize a new URL request object. We can look up the declaration of this method on the [Apple Developer Website](https://developer.apple.com/documentation/foundation/nsbundle/1409352-initwithurl?language=objc "Apple Developer Website - initWithURL Instance Method"):

```objectivec
- (instancetype)initWithURL:(NSURL *)url;
```

Using this information we can write a Frida script that intercepts the `initWithURL:` method and prints the URL passed to the method. The full script is below. Make sure you read the code and inline comments to understand what's going on.

```python
import sys
import frida


# JavaScript to be injected
frida_code = """

    // Obtain a reference to the initWithURL: method of the NSURLRequest class
    var URL = ObjC.classes.NSURLRequest["- initWithURL:"];

    // Intercept the method
    Interceptor.attach(URL.implementation, {
        onEnter: function(args) {
            // Get a handle on NSString
            var NSString = ObjC.classes.NSString;

            // Obtain a reference to the NSLog function, and use it to print the URL value
            // args[2] refers to the first method argument (NSURL *url)
            var NSLog = new NativeFunction(Module.findExportByName('Foundation', 'NSLog'), 'void', ['pointer', '...']);

            // We should always initialize an autorelease pool before interacting with Objective-C APIs
            var pool = ObjC.classes.NSAutoreleasePool.alloc().init();

            try {
                // Creates a JS binding given a NativePointer.
                var myNSURL = new ObjC.Object(args[2]);

                // Create an immutable ObjC string object from a JS string object.
                var str_url = NSString.stringWithString_(myNSURL.toString());

                // Call the iOS NSLog function to print the URL to the iOS device logs
                NSLog(str_url);

                // Use Frida's console.log to print the URL to your terminal
                console.log(str_url);

            } finally {
                pool.release();
            }
        }
    });
"""

process = frida.get_usb_device().attach("Safari")
script = process.create_script(frida_code)
script.load()

sys.stdin.read()
```

Start Safari on the iOS device. Run the above Python script on your connected host and open the device log (as explained in the section "Monitoring System Logs" from the chapter "iOS Basic Security Testing"). Try opening a new URL in Safari, e.g. <https://github.com/OWASP/owasp-mstg>; you should see Frida's output in the logs as well as in your terminal.

![Frida Xcode Log](Images/Chapters/0x06c/frida-xcode-log.png) \

Of course, this example illustrates only one of the things you can do with Frida. To unlock the tool's full potential, you should learn to use its [JavaScript API](https://www.frida.re/docs/javascript-api/ "Frida JavaScript API reference"). The documentation section of the Frida website has a [tutorial](https://www.frida.re/docs/ios/ "Frida Tutorial") and [examples](https://www.frida.re/docs/examples/ios/ "Frida examples") for using Frida on iOS.

#### Process Exploration

When testing an app, process exploration can provide the tester with deep insights into the app process memory. It can be achieved via runtime instrumentation and allows to perform tasks such as:

- Retrieving the memory map and loaded libraries.
- Searching for occurrences of certain data.
- After doing a search, obtaining the location of a certain offset in the memory map.
- Performing a memory dump and inspect or reverse engineer the binary data _offline_.
- Reverse engineering a binary or Framework while it's running.

As you can see, these tasks are rather supportive and/or passive, they'll help us collect data and information that will support other techniques. Therefore, they're normally used in combination with other techniques such as method hooking.

In the following sections you will be using [r2frida](0x08-Testing-Tools.md#r2frida) to retrieve information straight from the app runtime. First start by opening an r2frida session to the target app (e.g. iGoat-Swift) that should be running on your iPhone (connected per USB). Use the following command:

```bash
$ r2 frida://usb//iGoat-Swift
```

##### Memory Maps and Inspection

You can retrieve the app's memory maps by running `\dm`:

```bash
[0x00000000]> \dm
0x0000000100b7c000 - 0x0000000100de0000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
0x0000000100de0000 - 0x0000000100e68000 rw- /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
0x0000000100e68000 - 0x0000000100e97000 r-- /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
...
0x0000000100ea8000 - 0x0000000100eb0000 rw-
0x0000000100eb0000 - 0x0000000100eb4000 r--
0x0000000100eb4000 - 0x0000000100eb8000 r-x /usr/lib/TweakInject.dylib
0x0000000100eb8000 - 0x0000000100ebc000 rw- /usr/lib/TweakInject.dylib
0x0000000100ebc000 - 0x0000000100ec0000 r-- /usr/lib/TweakInject.dylib
0x0000000100f60000 - 0x00000001012dc000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/Frameworks/Realm.framework/Realm
```

While you're searching or exploring the app memory, you can always verify where your current offset is located in the memory map. Instead of noting and searching for the memory address in this list you can simply run `\dm.`. You'll find an example in the following section "In-Memory Search".

If you're only interested into the modules (binaries and libraries) that the app has loaded, you can use the command `\il` to list them all:

```bash
[0x00000000]> \il
0x0000000100b7c000 iGoat-Swift
0x0000000100eb4000 TweakInject.dylib
0x00000001862c0000 SystemConfiguration
0x00000001847c0000 libc++.1.dylib
0x0000000185ed9000 Foundation
0x000000018483c000 libobjc.A.dylib
0x00000001847be000 libSystem.B.dylib
0x0000000185b77000 CFNetwork
0x0000000187d64000 CoreData
0x00000001854b4000 CoreFoundation
0x00000001861d3000 Security
0x000000018ea1d000 UIKit
0x0000000100f60000 Realm
```

As you might expect you can correlate the addresses of the libraries with the memory maps: e.g. the main app binary iGoat-Swift is located at `0x0000000100b7c000` and the Realm Framework at `0x0000000100f60000`.

You can also use objection to display the same information.

```bash
$ objection --gadget OWASP.iGoat-Swift explore

OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # memory list modules
Save the output by adding `--json modules.json` to this command

Name                              Base         Size                  Path
--------------------------------  -----------  --------------------  ------------------------------------------------------------------------------
iGoat-Swift                       0x100b7c000  2506752 (2.4 MiB)     /var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGo...
TweakInject.dylib                 0x100eb4000  16384 (16.0 KiB)      /usr/lib/TweakInject.dylib
SystemConfiguration               0x1862c0000  446464 (436.0 KiB)    /System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguratio...
libc++.1.dylib                    0x1847c0000  368640 (360.0 KiB)    /usr/lib/libc++.1.dylib
```

##### In-Memory Search

In-memory search is a very useful technique to test for sensitive data that might be present in the app memory.

See r2frida's help on the search command (`\/?`) to learn about the search command and get a list of options. The following shows only a subset of them:

```bash
[0x00000000]> \/?
 /      search
 /j     search json
 /w     search wide
 /wj    search wide json
 /x     search hex
 /xj    search hex json
...
```

You can adjust your search by using the search settings `\e~search`. For example, `\e search.quiet=true;` will print only the results and hide search progress:

```bash
[0x00000000]> \e~search
e search.in=perm:r--
e search.quiet=false
```

For now, we'll continue with the defaults and concentrate on string search. In this first example, you can start by searching for something that you know it should be located in the main binary of the app:

```bash
[0x00000000]> \/ iGoat
Searching 5 bytes: 69 47 6f 61 74
Searching 5 bytes in [0x0000000100b7c000-0x0000000100de0000]
...
hits: 509
0x100d7d332 hit2_0 iGoat_Swift24StringAnalysisExerciseVCC
0x100d7d3b2 hit2_1 iGoat_Swift28BrokenCryptographyExerciseVCC
0x100d7d442 hit2_2 iGoat_Swift23BackgroundingExerciseVCC
0x100d7d4b2 hit2_3 iGoat_Swift9AboutCellC
0x100d7d522 hit2_4 iGoat_Swift12FadeAnimatorV
```

Now take the first hit, seek to it and check your current location in the memory map:

```bash
[0x00000000]> s 0x100d7d332
[0x100d7d332]> \dm.
0x0000000100b7c000 - 0x0000000100de0000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
```

As expected, you are located in the region of the main iGoat-Swift binary (r-x, read and execute). In the previous section, you saw that the main binary is located between `0x0000000100b7c000` and `0x0000000100e97000`.

Now, for this second example, you can search for something that's not in the app binary nor in any loaded library, typically user input. Open the iGoat-Swift app and navigate in the menu to **Authentication** -> **Remote Authentication** -> **Start**. There you'll find a password field that you can overwrite. Write the string "owasp-mstg" but do not click on **Login** just yet. Perform the following two steps.

```bash
[0x00000000]> \/ owasp-mstg
hits: 1
0x1c06619c0 hit3_0 owasp-mstg
```

In fact, the string could be found at address `0x1c06619c0`. Seek `s` to there and retrieve the current memory region with `\dm.`.

```bash
[0x100d7d332]> s 0x1c06619c0
[0x1c06619c0]> \dm.
0x00000001c0000000 - 0x00000001c8000000 rw-
```

Now you know that the string is located in a rw- (read and write) region of the memory map.

Additionally, you can search for occurrences of the [wide version of the string](https://en.wikipedia.org/wiki/Wide_character "Wide character") (`\/w`) and, again, check their memory regions:

> This time we run the `\dm.` command for all `@@` hits matching the glob `hit5_*`.

```bash
[0x00000000]> \/w owasp-mstg
Searching 20 bytes: 6f 00 77 00 61 00 73 00 70 00 2d 00 6d 00 73 00 74 00 67 00
Searching 20 bytes in [0x0000000100708000-0x000000010096c000]
...
hits: 2
0x1020d1280 hit5_0 6f0077006100730070002d006d00730074006700
0x1030c9c85 hit5_1 6f0077006100730070002d006d00730074006700

[0x00000000]> \dm.@@ hit5_*
0x0000000102000000 - 0x0000000102100000 rw-
0x0000000103084000 - 0x00000001030cc000 rw-
```

They are in a different rw- region. Note that searching for the wide versions of strings is sometimes the only way to find them as you'll see in the following section.

In-memory search can be very useful to quickly know if certain data is located in the main app binary, inside a shared library or in another region. You may also use it to test the behavior of the app regarding how the data is kept in memory. For instance, you could continue the previous example, this time clicking on Login and searching again for occurrences of the data. Also, you may check if you still can find those strings in memory after the login is completed to verify if this _sensitive data_ is wiped from memory after its use.

##### Memory Dump

You can dump the app's process memory with [objection](0x08-Testing-Tools.md#objection) and [Fridump](https://github.com/Nightbringer21/fridump "Fridump"). To take advantage of these tools on a non-jailbroken device, the Android app must be repackaged with `frida-gadget.so` and re-signed. A detailed explanation of this process is in the section "[Dynamic Analysis on Non-Jailbroken Devices](#dynamic-analysis-on-non-jailbroken-devices "Dynamic Analysis on Non-Jailbroken Devices"). To use these tools on a jailbroken phone, simply have frida-server installed and running.

With objection it is possible to dump all memory of the running process on the device by using the command `memory dump all`.

```bash
$ objection explore

iPhone on (iPhone: 10.3.1) [usb] # memory dump all /Users/foo/memory_iOS/memory
Dumping 768.0 KiB from base: 0x1ad200000  [####################################]  100%
Memory dumped to file: /Users/foo/memory_iOS/memory
```

Alternatively you can use Fridump. First, you need the name of the app you want to dump, which you can get with `frida-ps`.

```bash
$ frida-ps -U
 PID  Name
----  ------
1026  Gadget
```

Afterwards, specify the app name in Fridump.

```bash
$ python3 fridump.py -u Gadget -s

Current Directory: /Users/foo/PentestTools/iOS/fridump
Output directory is set to: /Users/foo/PentestTools/iOS/fridump/dump
Creating directory...
Starting Memory dump...
Progress: [##################################################] 100.0% Complete

Running strings on all files:
Progress: [##################################################] 100.0% Complete

Finished! Press Ctrl+C
```

When you add the `-s` flag, all strings are extracted from the dumped raw memory files and added to the file `strings.txt`, which is stored in Fridump's dump directory.

In both cases, if you open the file in radare2 you can use its search command (`/`). Note that first we do a standard string search which doesn't succeed and next we search for a [wide string](https://en.wikipedia.org/wiki/Wide_character "Wide character"), which successfully finds our string "owasp-mstg".

```bash
$ r2 memory_ios
[0x00000000]> / owasp-mstg
Searching 10 bytes in [0x0-0x628c000]
hits: 0
[0x00000000]> /w owasp-mstg
Searching 20 bytes in [0x0-0x628c000]
hits: 1
0x0036f800 hit4_0 6f0077006100730070002d006d00730074006700
```

Next, we can seek to its address using `s 0x0036f800`  or `s hit4_0` and print it using `psw` (which stands for _print string wide_) or use `px` to print its raw hexadecimal values:

```bash
[0x0036f800]> psw
owasp-mstg

[0x0036f800]> px 48
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0036f800  6f00 7700 6100 7300 7000 2d00 6d00 7300  o.w.a.s.p.-.m.s.
0x0036f810  7400 6700 0000 0000 0000 0000 0000 0000  t.g.............
0x0036f820  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Note that in order to find this string using the `strings` command you'll have to specify an encoding using the `-e` flag and in this case `l` for 16-bit little-endian character.

```bash
$ strings -e l memory_ios | grep owasp-mstg
owasp-mstg
```

##### Runtime Reverse Engineering

Runtime reverse engineering can be seen as the on-the-fly version of reverse engineering where you don't have the binary data to your host computer. Instead, you'll analyze it straight from the memory of the app.

We'll keep using the iGoat-Swift app, open a session with r2frida `r2 frida://usb//iGoat-Swift` and you can start by displaying the target binary information by using the `\i` command:

```bash
[0x00000000]> \i
arch                arm
bits                64
os                  darwin
pid                 2166
uid                 501
objc                true
runtime             V8
java                false
cylang              true
pageSize            16384
pointerSize         8
codeSigningPolicy   optional
isDebuggerAttached  false
cwd                 /
```

Search all symbols of a certain module with `\is <lib>`, e.g. `\is libboringssl.dylib`.

The following does a case-insensitive search (grep) for symbols including "aes" (`~+aes`).

```bash
[0x00000000]> \is libboringssl.dylib~+aes
0x1863d6ed8 s EVP_aes_128_cbc
0x1863d6ee4 s EVP_aes_192_cbc
0x1863d6ef0 s EVP_aes_256_cbc
0x1863d6f14 s EVP_has_aes_hardware
0x1863d6f1c s aes_init_key
0x1863d728c s aes_cipher
0x0 u ccaes_cbc_decrypt_mode
0x0 u ccaes_cbc_encrypt_mode
...
```

Or you might prefer to look into the imports/exports. For example:

- List all imports of the main binary: `\ii iGoat-Swift`.
- List exports of the libc++.1.dylib library: `\iE /usr/lib/libc++.1.dylib`.

> For big binaries it's recommended to pipe the output to the internal less program by appending `~..`, i.e. `\ii iGoat-Swift~..` (if not, for this binary, you'd get almost 5000 lines printed to your terminal).

The next thing you might want to look at are the classes:

```bash
[0x00000000]> \ic~+passcode
PSPasscodeField
_UITextFieldPasscodeCutoutBackground
UIPasscodeField
PasscodeFieldCell
...
```

List class fields:

```bash
[0x19687256c]> \ic UIPasscodeField
0x000000018eec6680 - becomeFirstResponder
0x000000018eec5d78 - appendString:
0x000000018eec6650 - canBecomeFirstResponder
0x000000018eec6700 - isFirstResponder
0x000000018eec6a60 - hitTest:forEvent:
0x000000018eec5384 - setKeyboardType:
0x000000018eec5c8c - setStringValue:
0x000000018eec5c64 - stringValue
...
```

Imagine that you are interested into `0x000000018eec5c8c - setStringValue:`. You can seek to that address with `s 0x000000018eec5c8c`, analyze that function `af` and print 10 lines of its disassembly `pd 10`:

```bash
[0x18eec5c8c]> pd 10
╭ (fcn) fcn.18eec5c8c 35
│   fcn.18eec5c8c (int32_t arg1, int32_t arg3);
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 2 (vars 0, args 2)
│           0x18eec5c8c      f657bd         not byte [rdi - 0x43]      ; arg1
│           0x18eec5c8f      a9f44f01a9     test eax, 0xa9014ff4
│           0x18eec5c94      fd             std
│       ╭─< 0x18eec5c95      7b02           jnp 0x18eec5c99
│       │   0x18eec5c97      a9fd830091     test eax, 0x910083fd
│           0x18eec5c9c      f30300         add eax, dword [rax]
│           0x18eec5c9f      aa             stosb byte [rdi], al
│       ╭─< 0x18eec5ca0      e003           loopne 0x18eec5ca5
│       │   0x18eec5ca2      02aa9b494197   add ch, byte [rdx - 0x68beb665] ; arg3
╰           0x18eec5ca8      f4             hlt
```

Finally, instead of doing a full memory search for strings, you may want to retrieve the strings from a certain binary and filter them, as you'd do _offline_ with radare2. For this you have to find the binary, seek to it and then run the `\iz` command.

> It's recommended to apply a filter with a keyword `~<keyword>`/`~+<keyword>` to minimize the terminal output. If just want to explore all results you can also pipe them to the internal less `\iz~..`.

```bash
[0x00000000]> \il~iGoa
0x00000001006b8000 iGoat-Swift
[0x00000000]> s 0x00000001006b8000
[0x1006b8000]> \iz
Reading 2.390625MB ...
Do you want to print 8568 lines? (y/N) N
[0x1006b8000]> \iz~+hill
Reading 2.390625MB ...
[0x1006b8000]> \iz~+pass
Reading 2.390625MB ...
0x00000001006b93ed  "passwordTextField"
0x00000001006bb11a  "11iGoat_Swift20KeychainPasswordItemV0C5ErrorO"
0x00000001006bb164  "unexpectedPasswordData"
0x00000001006d3f62  "Error reading password from keychain - "
0x00000001006d40f2  "Incorrect Password"
0x00000001006d4112  "Enter the correct password"
0x00000001006d4632  "T@"UITextField",N,W,VpasswordField"
0x00000001006d46f2  "CREATE TABLE IF NOT EXISTS creds (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT);"
0x00000001006d4792  "INSERT INTO creds(username, password) VALUES(?, ?)"
```

To learn more, please refer to the [r2frida wiki](https://github.com/enovella/r2frida-wiki/blob/master/README.md "r2frida Wiki").

## References

- Apple's Entitlements Troubleshooting - <https://developer.apple.com/library/content/technotes/tn2415/_index.html>
- Apple's Code Signing - <https://developer.apple.com/support/code-signing/>
- Cycript Manual - <http://www.cycript.org/manual/>
- iOS Instrumentation without Jailbreak - <https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/october/ios-instrumentation-without-jailbreak/>
- Frida iOS Tutorial - <https://www.frida.re/docs/ios/>
- Frida iOS Examples - <https://www.frida.re/docs/examples/ios/>
- r2frida Wiki - <https://github.com/enovella/r2frida-wiki/blob/master/README.md>
- [#miller] - Charlie Miller, Dino Dai Zovi. The iOS Hacker's Handbook. Wiley, 2012 - <https://www.wiley.com/en-us/iOS+Hacker%27s+Handbook-p-9781118204122>
- [#levin] Jonathan Levin. Mac OS X and iOS Internals: To the Apple's Core. Wiley, 2013 - <http://newosxbook.com/MOXiI.pdf>
