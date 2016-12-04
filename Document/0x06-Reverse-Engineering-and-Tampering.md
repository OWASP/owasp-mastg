# Tampering and Reverse Engineering

Reverse engineering and tampering techniques have long belonged into the realm of crackers, modders, malware analysts, and other more exotic professions. For "traditional" security testers and researchers, reverse engineering has been more of a complementary, nice-to-have-type skill that wasn't all that useful in 99% of day-to-day work. But the tides are turning: Mobile app black-box testing increasingly requires testers to disassemble compiled apps, apply patches, and tamper with binary code or even live processes. The fact that many mobile apps implement defenses against unwelcome tampering doesn't make things easier for us.

Mobile security testers should be able to understand basic reverse engineering concepts. It goes without saying that they should also know mobile devices and operating systems inside out: The processor architecture, executable format, programming language intricacies, and so forth.

Reverse engineering is an art, and describing every available facet of it would fill a whole library. The sheer range techniques and possible specializations is mind-blowing: One can spend years working on a very specific, isolated sub-problem, such as automating malware analysis or developing novel de-obfuscation methods. Security testers are generalists: To be effective reverse engineers, they must be able filter through the vast amount of information to build a workable methodology.

There is no generic reverse engineering process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.

## Why should you even bother?

To sum things up, mobile security testing requires at least basic reverse engineering skills for several reasons:

**1. To enable black-box testing of mobile apps.** Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and E2E encryption could prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

**3. To assess resiliency against reverse engineering.**  Apps that implement software protections according to MASVS L3 or L4 should be resilient against reverse engineering. In this case, testing the reverse engineering defenses ("resiliency assessment") is part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses. Advanced reverse engineering skills are required to perform this kind of test.

## Basic Tampering Techniques

Tampering is the process of making changes to a mobile app either the compiled app, or the running process) or its environment to affect changes in its behavior. For example, and app might refuse to running on your rooted test device, making it impossible to run some of your tests. In cases like that, you'll want to alter that particular behavior.

In the following section we'll give a high level overview of the techniques most commonly used in mobile app security testing. Later, we'll drill down into  OS-specific details for both Android and iOS.

### Patching

Patching means making changes to the compiled app - e.g. changing code in a binary executable file(s), modifying Java bytecode, or tampering with resources. Patches can be applied in any number of ways, from decompiling and re-assembling an app, to editing binary files in a hex editor - anything goes (this rule applies to all of reverse engineering). We'll give some detailed examples for useful patches in later chapters.

One thing to keep in mind is that modern mobile OSes strictly enforce code signing, so running modified apps is not as straightforward as it used to be in traditional Desktop environments. Yep, security experts had a much easier life in the 90ies! Fortunately, this is not all that difficult to do if you work on your own device - it simply means that you need to re-sign the app, or disable the default code signing facilities to run modified code.

### Code Injection

Code injection is a very powerful technique that allows you to explore and modify processes during runtime. The injection process can be implemented in various ways*, but you'll get by without knowing all the details thanks to freely available, well-documented tools that automate it. These tools give you direct access to process memory and important structures such as live objects instantiated by the app, and come with many useful utility functions for resolving loaded libraries, hooking methods and native functions, and more. Tampering with process memory is more difficult to detect than patching files, making in the preferred method in the majority of cases.

The two best-known code injection frameworks are Substrate and FRIDA. The main difference between the two is design philosophy: FRIDA aims to be a full-blown "dynamic instrumentation framework" that incorporates both code injection and language bindings, while Substrate only handles code injection and hooking, but doesn't include an injectable JavaScript VM and console. It does however come with a tool called Cynject that provides code injection support for Cycrypt, the programming environment (a.k.a. "Cycript-to-JavaScript" compiler) authored by Saurik of Cydia fame. Ultimately, you can achieve the same goals with both Cycript/Substrate and FRIDA, except that Substrate doesn't support runtime code injection on Android.

To complicate things, FRIDA's authors also created a fork of Cycript named ["frida-cycript"](https://github.com/nowsecure/frida-cycript) that replaces Cycript's runtime with a Frida-based runtime called Mjølner. This enables Cycript run on all the platforms and architectures maintained by frida-core. The release was accompanies by a blog post by Ole titled "Cycript on Steroids", which prompted a vitriolic response by Saurik on [Reddit](https://www.reddit.com/r/ReverseEngineering/comments/50uweq/cycript_on_steroids_pumping_up_portability_and/).

#### Cycript and Cynject

Cynject is a tool that provides code injection support for C. It can inject a JavaScriptCore VM into a running process on iOS. Through Cycript's foreign function interface, users can interface with C code, including support for primitive types, pointers, structs and C Strings, as well as Objective-C objects and data structures. It is even possible to access and instantiate Objective-C classes inside the running process. Some examples for the use of Cycript are listed in the iOS chapter.

#### Dynamic Instrumentation with FRIDA

FRIDA is a dynamic instrumentation framework that lets the user you inject JavaScript into native apps on Windows, Mac, Linux, iOS, Android, and QNX.

Its injection code uses ptrace to hijack a thread in a running process. This thread is used to allocate a chunk of memory and populate it with a mini-bootstrapper. The bootstrapper starts a fresh thread, connects to the Frida debugging server running on the device, and loads a dynamically generated library file containing the Frida agent and instrumentation code. The original, hijacked thread is restored to its original state and resumed, and execution of the process continues as usual.

FRIDA really awesome is that it injects a complete JavaScript runtime into the process, along with a powerful API that provides a wealth of useful functionality, including calling and hooking of native functions and injecting structured data into memory. It also supports interaction with the Android Java runtime, such as interacting with objects inside the VM.

![Frida](images/frida.png)

*FRIDA Architecture, source: http://www.frida.re/docs/hacking/*

Here are some more APIs FRIDA offers:

-	Instantiate Java objects and call static and non-static class methods;
-	Replace Java method implementations;
-	Enumerate live instances of specific classes by scanning the Java heap (Dalvik only);
-	Scan process memory for occurrences of a string;
-	Intercept native function calls to run your own code at function entry and exit.

Some features unfortunately don’t work yet on current Android devices platforms. Most notably, the FRIDA Stalker - a code tracing engine based on dynamic recompilation - does not support ARM at the time of this writing (version 7.2.0). Also, support for ART has been included only recently, so the Dalvik runtime is still better supported.

### Hooking Frameworks

Cydia Substrate (formerly called MobileSubstrate) is the de facto framework that allows 3rd-party developers to provide run-time patches (“Cydia Substrate extensions”) to system functions,

TODO: Introduce concepts and give examples: Xposed, Substrate.

## Static / Dynamic Binary Analysis

Reverse engineering is the process of reconstructing the semantics of the original source code from a compiled program. In other words, you take the program apart, run it, simulate parts of it, and do other unspeakable things to in order to understand what exactly it is doing and how.

### Using Disassemblers and Decompilers

Disassemblers and decompilers allow you to translate an app's binary code or byte-code back into a more or less understandable format. In the case of native binaries, you'll usually obtain assembler code matching the architecture the app was compiled for. Android Java apps can be disassembled to Smali (an Assembler language for the dex format), and also quite easily converted back to Java code.  

TODO: introduce a few standard tools, IDA Pro Hopper, Radare2, JEB (?)

TODO: Talk about IDA Scripting and the many plugins developed by the community

### Debugging

### Execution Tracing

### Dynamic Binary Instrumentation

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download. The [Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html) contains specific compilation instructions for Android.

## Automated De-Obfuscation Attacks

TODO: Introduce advanced concepts

### Binary Analysis Frameworks

TODO: Introduce RE frameworks

[Miasm](https://github.com/cea-sec/miasm)
[Metasm](https://github.com/jjyg/metasm)

### Symbolic Execution


### Domain-specific attacks
