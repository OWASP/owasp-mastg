# Tampering and Reverse Engineering

Reverse engineering and tampering techniques have long been associated with crackers, modders and malware analysts. For "traditional" security testers and researchers, reverse engineering has always been more of a complementary, nice-to-have-type skill that wasn't all that useful in 99% of cases. However, the situation is changing: Mobile app black-box testing requires testers to do perform  static/dynamic analysis, apply patches, and tamper with the target app - sometimes, the test cannot be performed otherwise. It doesn't help that mobile apps increasingly implement defenses to prevent said tampering.

Every mobile security tester should know at least basic reverse engineering techniques as well as the particular mobile environment(s): The processor architecture, operating system, binary format, programming language, and so on. They should also keep up-to-date with the newest techniques and tools available to reverse engineers.

Reverse engineering is an art, and describing every available facet and tool would fill a whole library. The best protection mechanisms are based on original ideas, so there is no generic process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.

Mobile app security testing requires at least basic reverse engineering skills for several reasons:

**1. To enable black-box testing of mobile apps.** Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and E2E encryption could prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

**3. To assess resiliency against reverse engineering.**  Apps that implement software protections according to MASVS L3 or L4 should be resilient against reverse engineering. In this case, testing the reverse engineering defenses ("resiliency assessment") is part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses. Advanced reverse engineering skills are required to perform this kind of test.

## Basic Tampering Techniques

In the following section we'll give a high level overview of the techniques most commonly used in mobile app security testing. Right after this chapter, we'll drill down into the OS-specific details for both Android and iOS.

### Patching

Patching means making changes to the compiled app - e.g. binary executable file(s), Java bytecode, or other resources - with the goal of modifying some aspect of the app. In basic security testing, this is useful for removing restrictions such as SSL Pinning that may otherwise prevent you from running certain test cases. Patches can be applied in any number of ways, from decompiling and re-compiling an app, to editing the binary code in a hex editor - everything goes as long as you're producing a valid binary. You'll find some examples for useful patches in the OS-specific chapters.

All modern mobile OSes do some form of code signing, so running modified apps is not as straightforward as it used to be in traditional Desktop environments. You'll either have to re-sign the app, or disable the default code signing facilities to run modified code (fortunately, this is not all that difficult to do on your own device).

### Code Injection

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

## Reverse Engineering Basics

TODO: Static vs. dynamic analysis.

### Disassembling and Decompiling Apps

Disassemblers and decompilers allow you to translate an app's binary code or byte-code back into a more or less understandable format. In the case of native binaries, you'll usually obtain assembler code matching the architecture the app was compiled for. Android Java apps can be disassembled to Smali (an Assembler language for the dex format), or quite easily converted back to Java code.  

IDA
IDA (Interactive Disassembler) Pro is a commercial disassembler that supports a multitude of architectures. It is compatible with all executable formats and architectures used in Android and iOS devices, and comes with build-in debuggers for Android (Java and native).


Hopper

JEB

### Debugging

### Execution Tracing

### Dynamic Binary Instrumentation

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download. The [Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html) contains specific compilation instructions for Android.

### De-Obfuscation Using Binary Analysis Frameworks

[Miasm](https://github.com/cea-sec/miasm) is a free and open source (GPLv2) reverse engineering framework. Miasm aims to analyze / modify / generate binary programs. Here is a non exhaustive list of features:

Opening / modifying / generating PE / ELF 32 / 64 LE / BE using Elfesteem
Assembling / Disassembling X86 / ARM / MIPS / SH4 / MSP430
Representing assembly semantic using intermediate language
Emulating using JIT (dynamic code analysis, unpacking, ...)
Expression simplification for automatic de-obfuscation

[Metasm](https://github.com/jjyg/metasm) is a cross-architecture assembler, disassembler, compiler, linker and debugger.

It has some advanced features such as remote process manipulation, GCC-compatible preprocessor, automatic backtracking in the disassembler ("slicing"), C headers shrinking, linux/windows debugging API interface, a C compiler, a gdb-server compatible debugger, and various advanced features. It is written in pure Ruby.

Miasm is a Python open source reverse engineering framework.

http://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html
