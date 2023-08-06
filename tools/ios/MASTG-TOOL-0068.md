---
title: SwiftShield
platform: ios
refs:
  - https://github.com/rockbruno/swiftshield
---

[SwiftShield](https://github.com/rockbruno/swiftshield "SwiftShield") is a tool that generates irreversible, encrypted names for your iOS project's objects (including your Pods and Storyboards). This raises the bar for reverse engineers and will produce less helpful output when using reverse engineering tools such as class-dump and Frida.

> Warning: SwiftShield irreversibly overwrites all your source files. Ideally, you should have it run only on your CI server, and on release builds.

A sample Swift project is used to demonstrate the usage of SwiftShield.

- Check out [sushi2k/SwiftSecurity](https://github.com/sushi2k/SwiftSecurity).
- Open the project in Xcode and make sure that the project is building successfully (Product / Build or Apple-Key + B).
- [Download](https://github.com/rockbruno/swiftshield/releases "SwiftShield Download") the latest release of SwiftShield and unzip it.
- Go to the directory where you downloaded SwiftShield and copy the swiftshield executable to `/usr/local/bin`:

```bash
cp swiftshield/swiftshield /usr/local/bin/
```

- In your terminal go into the SwiftSecurity directory (which you checked out in step 1) and execute the command swiftshield (which you downloaded in step 3):

```bash
$ cd SwiftSecurity
$ swiftshield -automatic -project-root . -automatic-project-file SwiftSecurity.xcodeproj -automatic-project-scheme SwiftSecurity
SwiftShield 3.4.0
Automatic mode
Building project to gather modules and compiler arguments...
-- Indexing ReverseEngineeringToolsChecker.swift --
Found declaration of ReverseEngineeringToolsChecker (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC)
Found declaration of amIReverseEngineered (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC20amIReverseEngineeredSbyFZ)
Found declaration of checkDYLD (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC9checkDYLD33_D6FE91E9C9AEC4D13973F8ABFC1AC788LLSbyFZ)
Found declaration of checkExistenceOfSuspiciousFiles (s:13SwiftSecurity30ReverseEngineeringToolsCheckerC31checkExistenceOfSuspiciousFiles33_D6FE91E9C9AEC4D13973F8ABFC1AC788LLSbyFZ)
...
```

SwiftShield is now detecting class and method names and is replacing their identifier with an encrypted value.

In the original source code you can see all the class and method identifiers:

<img src="Images/Chapters/0x06j/no_obfuscation.jpg" width="400px" />

SwiftShield was now replacing all of them with encrypted values that leave no trace to their original name or intention of the class/method:

<img src="Images/Chapters/0x06j/swiftshield_obfuscated.jpg" width="400px" />

After executing `swiftshield` a new directory will be created called `swiftshield-output`. In this directory another directory is created with a timestamp in the folder name. This directory contains a text file called `conversionMap.txt`, that maps the encrypted strings to their original values.

```bash
$ cat conversionMap.txt
//
// SwiftShield Conversion Map
// Automatic mode for SwiftSecurity, 2020-01-02 13.51.03
// Deobfuscate crash logs (or any text file) by running:
// swiftshield -deobfuscate CRASH_FILE -deobfuscate_map THIS_FILE
//

ViewController ===> hTOUoUmUcEZUqhVHRrjrMUnYqbdqWByU
viewDidLoad ===> DLaNRaFbfmdTDuJCPFXrGhsWhoQyKLnO
sceneDidBecomeActive ===> SUANAnWpkyaIWlGUqwXitCoQSYeVilGe
AppDelegate ===> KftEWsJcctNEmGuvwZGPbusIxEFOVcIb
Deny_Debugger ===> lKEITOpOvLWCFgSCKZdUtpuqiwlvxSjx
Button_Emulator ===> akcVscrZFdBBYqYrcmhhyXAevNdXOKeG
```

This is needed for [deobfuscating encrypted crash logs](https://github.com/rockbruno/swiftshield#-deobfuscating-encrypted-crash-logs "Deobfuscating encrypted Crash logs").

Another example project is available in SwiftShield's [Github repo](https://github.com/rockbruno/swiftshield/tree/master/ExampleProject "SwiftShieldExample"), that can be used to test the execution of SwiftShield.