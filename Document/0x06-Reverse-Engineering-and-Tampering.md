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

Tampering is the process of making changes to a mobile app either the compiled app, or the running process) or its environment to affect changes in behavior. For example, and app might refuse to running on your rooted test device, making it impossible to run some of the test cases. In that case, you'll want to deactivate that particular behavior so you can proceed with the test.

In the following section we'll give a high level overview of the techniques most commonly used in mobile app security testing. Right after this chapter, we'll drill down into the OS-specific details for both Android and iOS.

### Patching

Patching means making changes to the compiled app - e.g. changing code in a binary executable file(s), modifying Java bytecode, or tampering with resources. Patches can be applied in any number of ways, from decompiling and re-assembling an app, to editing binary files in a hex editor - anything goes (this is true in all of reverse engineering). We'll give some OS-specific examples for patching later on.

All modern mobile OSes enforce some form of code signing, so running modified apps is not as straightforward as it used to be in traditional Desktop environments (oh good old times). You'll either have to re-sign the app, or disable the default code signing facilities to run modified code. Fortunately, this is not all that difficult to do if you work on your own device.

### Code Injection

Code injection is a very powerful technique that allows you to explore and modify processes during runtime. The injection process can be implemented in various ways, but you'll get by without knowing all the details thanks to freely available, well-documented tools that automate it. These tools give you direct access to process memory and important structures such as live objects instantiated by the app, and come with many useful utility functions for resolving loaded libraries, hooking methods and native functions, and more. Tampering with process memory is more difficult to detect than patching files, making in the preferred method in the majority of cases.

The two best-known code injection frameworks are Cycript and Frida. Cycript - pronounced "sssscript" - is a "Cycript-to-JavaScript" compiler authored by Saurik of Cydia fame that uses JavaScriptCore for its virtual machine. Cycript is traditionally used in the iOS world. It also runs standalone on Android, however without injection support. It is based on a Java VM that can be injected into a running process using Cydia Substrate. The user then communicates with process through the Cycript console interface.

Cycript implements a foreign function interface that allows users to interface with C code, including support for primitive types, pointers, structs and C Strings, as well as Objective-C objects and data structures. It is even possible to access and instantiate Objective-C classes inside the running process. Some examples for the use of Cycript are listed in the iOS chapter.

FRIDA is the Swiss army knife of Android Reverse Engineering. Its magic is based on code injection: Upon attaching to a process, FRIDA uses ptrace to hijack an existing thread in the process. The hijacked thread is used to allocate a chunk of memory and populate it with a mini-bootstrapper. The bootstrapper then starts a fresh thread, connects to the Frida debugging server running on the device, and loads a dynamically generated library file containing the Frida agent and instrumentation code. The original, hijacked thread is restored to its original state and resumed, and execution of the process continues as usual (being completely unaware of what has happened to it, unless it scans its own memory or employs some other form of runtime integrity check).

![Frida](images/frida.png)
*FRIDA Architecture, source: http://www.frida.re/docs/hacking/*

So far so good. What makes FRIDA really awesome is that it injects a complete JavaScript runtime into the process, along with a powerful API that provides a wealth of useful functionality, including calling and hooking of native functions and injecting structured data into memory. It also supports interaction with the Android Java runtime, such as interacting with objects inside the VM.

Here are some more awesome APIs FRIDA offers:

-	Instantiate Java objects and call static and non-static class methods;
-	Replace Java method implementations;
-	Enumerate live instances of specific classes by scanning the Java heap (Dalvik only);
-	Scan process memory for occurrences of a string;
-	Intercept native function calls to run your own code at function entry and exit.

Some features unfortunately don’t work yet on current Android devices platforms. Most notably, the FRIDA Stalker - a code tracing engine based on dynamic recompilation - does not support ARM at the time of this writing (version 7.2.0). Also, support for ART has been included only recently, so the Dalvik runtime is still better supported.

### Hooking Frameworks

TODO: Introduce concepts and give examples: Xposed, Substrate.

## Basic Static / Dynamic Analysis

TODO: Static vs. dynamic analysis.

### Using Disassemblers and Decompilers

Disassemblers and decompilers allow you to translate an app's binary code or byte-code back into a more or less understandable format. In the case of native binaries, you'll usually obtain assembler code matching the architecture the app was compiled for. Android Java apps can be disassembled to Smali (an Assembler language for the dex format), and also quite easily converted back to Java code.  

TODO: introduce a few standard tools, IDA Pro Hopper, Radare2, JEB (?)

TODO: Talk about IDA Scripting and the many plugins developed by the community

### Debugging

### Execution Tracing

### Dynamic Binary Instrumentation

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download. The [Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html) contains specific compilation instructions for Android.

## Advanced Analysis and De-Obfuscation

TODO: Introduce advanced concepts

### Binary Analysis Frameworks

TODO: Introduce RE frameworks

[Miasm](https://github.com/cea-sec/miasm)
[Metasm](https://github.com/jjyg/metasm)
