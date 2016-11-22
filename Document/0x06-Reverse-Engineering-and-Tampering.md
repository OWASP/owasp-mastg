# Tampering and Reverse Engineering

Mobile app security testing requires at least basic reverse engineering skills for several reasons.

**1. To enable black-box testing of mobile apps.** Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and E2E encryption could prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

**3. To assess resiliency against reverse engineering.**  Apps that implement software protections according to MASVS L3 or L4 should be resilient against reverse engineering. In this case, testing the reverse engineering defenses ("resiliency assessment") is part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses. Advanced reverse engineering skills are required to perform this kind of test.

Testers should be proficient in general reverse engineering techniques as well as the particular environment: The target architecture, operating system, binary format, programming language, and so on. They should also keep up-to-date with the newest techniques and tools available to reverse engineers.

Reverse engineering is a creative process: The best protection mechanisms are based on original ideas, so there is no generic process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.

## Basic Tampering Techniques

### Patching

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

### Disassembling and Decompiling Apps

### Debugging

### Execution Tracing

### Dynamic Binary Instrumentation

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download. The [Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html) contains specific compilation instructions for Android.

### Using Binary Analysis Frameworks for De-Obfuscation

[Miasm](https://github.com/cea-sec/miasm) is a free and open source (GPLv2) reverse engineering framework. Miasm aims to analyze / modify / generate binary programs. Here is a non exhaustive list of features:

Opening / modifying / generating PE / ELF 32 / 64 LE / BE using Elfesteem
Assembling / Disassembling X86 / ARM / MIPS / SH4 / MSP430
Representing assembly semantic using intermediate language
Emulating using JIT (dynamic code analysis, unpacking, ...)
Expression simplification for automatic de-obfuscation

[Metasm](https://github.com/jjyg/metasm) is a cross-architecture assembler, disassembler, compiler, linker and debugger.

It has some advanced features such as remote process manipulation, GCC-compatible preprocessor, automatic backtracking in the disassembler ("slicing"), C headers shrinking, linux/windows debugging API interface, a C compiler, a gdb-server compatible debugger, and various advanced features. It is written in pure Ruby.

Miasm is a Python open source reverse engineering framework. T

http://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html
