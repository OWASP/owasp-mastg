---
masvs_category: MASVS-RESILIENCE
platform: all
---

# Mobile App Tampering and Reverse Engineering

Reverse engineering and tampering techniques have long belonged to the realm of crackers, modders, malware analysts, etc. For "traditional" security testers and researchers, reverse engineering has been more of a complementary skill. But the tides are turning: mobile app black-box testing increasingly requires disassembling compiled apps, applying patches, and tampering with binary code or even live processes. The fact that many mobile apps implement defenses against unwelcome tampering doesn't make things easier for security testers.

Reverse engineering a mobile app is the process of analyzing the compiled app to extract information about its source code. The goal of reverse engineering is _comprehending_ the code.

_Tampering_ is the process of changing a mobile app (either the compiled app or the running process) or its environment to affect its behavior. For example, an app might refuse to run on your rooted test device, making it impossible to run some of your tests. In such cases, you'll want to alter the app's behavior.

Mobile security testers are served well by understanding basic reverse engineering concepts. They should also know mobile devices and operating systems inside out: processor architecture, executable format, programming language intricacies, and so forth.

Reverse engineering is an art, and describing its every facet would fill a whole library. The sheer range of techniques and specializations is mind-blowing: one can spend years working on a very specific and isolated sub-problem, such as automating malware analysis or developing novel de-obfuscation methods. Security testers are generalists; to be effective reverse engineers, they must filter through the vast amount of relevant information.

There is no generic reverse engineering process that always works. That said, we'll describe commonly used methods and tools later in this guide, and give examples of tackling the most common defenses.

## Why You Need It

Mobile security testing requires at least basic reverse engineering skills for several reasons:

**1. To enable black-box testing of mobile apps.** Modern apps often include controls that will hinder dynamic analysis. SSL pinning and end-to-end (E2E) encryption sometimes prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. You must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code helps you understand the internal logic of the app. It also allows you to identify flaws such as hardcoded credentials.

**3. To assess resilience against reverse engineering.** Apps that implement the software protection measures listed in the Mobile Application Security Verification Standard Anti-Reversing Controls (MASVS-R) should withstand reverse engineering to a certain degree. To verify the effectiveness of such controls, the tester may perform a _resilience assessment_ as part of the general security test. For the resilience assessment, the tester assumes the role of the reverse engineer and attempts to bypass defenses.

Before we dive into the world of mobile app reversing, we have some good news and some bad news. Let's start with the good news:

**Ultimately, the reverse engineer always wins.**

This is particularly true in the mobile industry, where the reverse engineer has a natural advantage: the way mobile apps are deployed and sandboxed is by design more restrictive than the deployment and sandboxing of classical Desktop apps, so including the rootkit-like defensive mechanisms often found in Windows software (e.g., DRM systems) is simply not feasible. The openness of Android allows reverse engineers to make favorable changes to the operating system, aiding the reverse engineering process. iOS gives reverse engineers less control, but defensive options are also more limited.

The bad news is that dealing with multi-threaded anti-debugging controls, cryptographic white-boxes, stealthy anti-tampering features, and highly complex control flow transformations is not for the faint-hearted. The most effective software protection schemes are proprietary and won't be beaten with standard tweaks and tricks. Defeating them requires tedious manual analysis, coding, frustration and, depending on your personality, sleepless nights and strained relationships.

It's easy for beginners to get overwhelmed by the sheer scope of reversing. The best way to get started is to set up some basic tools (see the relevant sections in the Android and iOS reversing chapters) and start with simple reversing tasks and crackmes. You'll need to learn about the assembler/bytecode language, the operating system, obfuscations you encounter, and so on. Start with simple tasks and gradually level up to more difficult ones.

In the following section, we'll give an overview of the techniques most commonly used in mobile app security testing. In later chapters, we'll drill down into OS-specific details of both Android and iOS.

## Basic Tampering Techniques

### Binary Patching

_Patching_ is the process of changing the compiled app, e.g., changing code in binary executables, modifying Java bytecode, or tampering with resources. This process is known as _modding_ in the mobile game hacking scene. Patches can be applied in many ways, including editing binary files in a hex editor and decompiling, editing, and re-assembling an app. We'll give detailed examples of useful patches in later chapters.

Keep in mind that modern mobile operating systems strictly enforce code signing, so running modified apps is not as straightforward as it used to be in desktop environments. Security experts had a much easier life in the 90s! Fortunately, patching is not very difficult if you work on your own device. You simply have to re-sign the app or disable the default code signature verification facilities to run modified code.

### Code Injection

Code injection is a very powerful technique that allows you to explore and modify processes at runtime. Injection can be implemented in various ways, but you'll get by without knowing all the details thanks to freely available, well-documented tools that automate the process. These tools give you direct access to process memory and important structures such as live objects instantiated by the app. They come with many utility functions that are useful for resolving loaded libraries, hooking methods and native functions, and more. Process memory tampering is more difficult to detect than file patching, so it is the preferred method in most cases.

@MASTG-TOOL-0139, @MASTG-TOOL-0031, and @MASTG-TOOL-0027 are the most widely used hooking and code injection frameworks in the mobile industry. The three frameworks differ in design philosophy and implementation details: ElleKit and Xposed focus on code injection and/or hooking, while Frida aims to be a full-blown "dynamic instrumentation framework", incorporating code injection, language bindings, and an injectable JavaScript VM and console.

We'll include examples of all three frameworks. We recommend starting with Frida because it is the most versatile of the three (for this reason, we'll also include more Frida details and examples). Notably, Frida can inject a JavaScript VM into a process on both Android and iOS, while injection with ElleKit only works on iOS and Xposed only works on Android. Ultimately, however, you can of course achieve many of the same goals with either framework.

## Static and Dynamic Binary Analysis

Reverse engineering is the process of reconstructing the semantics of a compiled program's source code. In other words, you take the program apart, run it, simulate parts of it, and do other unspeakable things to it to understand what it does and how.

### Using Disassemblers and Decompilers

Disassemblers and decompilers allow you to translate an app's binary code or bytecode back into a more or less understandable format. By using these tools on native binaries, you can obtain assembler code that matches the architecture the app was compiled for. Disassemblers convert machine code to assembly code which in turn is used by decompilers to generate equivalent high-level language code. Android Java apps can be disassembled to smali, which is an assembly language for the DEX format used by Dalvik, Android's Java VM. Smali assembly can also be quite easily decompiled back to equivalent Java code.

In theory, the mapping between assembly and machine code should be one-to-one, and therefore it may give the impression that disassembling is a simple task. But in practice, there are multiple pitfalls such as:

- Reliable distinction between code and data.
- Variable instruction size.
- Indirect branch instructions.
- Functions without explicit CALL instructions within the executable's code segment.
- Position independent code (PIC) sequences.
- Hand crafted assembly code.

Similarly, decompilation is a very complicated process, involving many deterministic and heuristic based approaches. As a consequence, decompilation is usually not really accurate, but nevertheless very helpful in getting a quick understanding of the function being analyzed. The accuracy of decompilation depends on the amount of information available in the code being decompiled and the sophistication of the decompiler. In addition, many compilation and post-compilation tools introduce additional complexity to the compiled code in order to increase the difficulty of comprehension and/or even decompilation itself. Such code referred to as [_obfuscated code_](#obfuscation).

Over the past decades many tools have perfected the process of disassembly and decompilation, producing output with high fidelity. Advanced usage instructions for any of the available tools can often easily fill a book of their own. The best way to get started is to simply pick up a tool that fits your needs and budget and get a well-reviewed user guide. In this section, we will provide an introduction to some of those tools and in the subsequent "Reverse Engineering and Tampering" Android and iOS chapters we'll focus on the techniques themselves, especially those that are specific to the platform at hand.

### Obfuscation

Obfuscation is the process of transforming code and data to make it more difficult to comprehend (and sometimes even difficult to disassemble). It is usually an integral part of the software protection scheme. Obfuscation isn't something that can be simply turned on or off, programs can be made incomprehensible, in whole or in part, in many ways and to different degrees.

> Note: All presented techniques below will not stop someone with enough time and budget from reverse engineering your app. However, combining these techniques will make their job significantly harder. The aim is thus to discourage reverse engineers from performing further analysis and not making it worth the effort.

The following techniques can be used to obfuscate an application:

- Name obfuscation
- Instruction substitution
- Control flow flattening
- Dead code injection
- String encryption
- Packing

#### Name Obfuscation

The standard compiler generates binary symbols based on class and function names from the source code. Therefore, if no obfuscation is applied, symbol names remain meaningful and can easily be extracted from the app binary. For instance, a function which detects a jailbreak can be located by searching for relevant keywords (e.g. "jailbreak"). The listing below shows the disassembled function `JailbreakDetectionViewController.jailbreakTest4Tapped` from the @MASTG-APP-0024.

```assembly
__T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

After the obfuscation we can observe that the symbol's name is no longer meaningful as shown on the listing below.

```assembly
__T07DVIA_v232zNNtWKQptikYUBNBgfFVMjSkvRdhhnbyyFySbyypF:
stp        x22, x21, [sp, #-0x30]!
mov        rbp, rsp
```

Nevertheless, this only applies to the names of functions, classes and fields. The actual code remains unmodified, so an attacker can still read the disassembled version of the function and try to understand its purpose (e.g. to retrieve the logic of a security algorithm).

#### Instruction Substitution

This technique replaces standard binary operators like addition or subtraction with more complex representations. For example, an addition `x = a + b` can be represented as `x = -(-a) - (-b)`. However, using the same replacement representation could be easily reversed, so it is recommended to add multiple substitution techniques for a single case and introduce a random factor. This technique can be reversed during decompilation, but depending on the complexity and depth of the substitutions, reversing it can still be time consuming.

#### Control Flow Flattening

Control flow flattening replaces original code with a more complex representation. The transformation breaks the body of a function into basic blocks and puts them all inside a single infinite loop with a switch statement that controls the program flow. This makes the program flow significantly harder to follow because it removes the natural conditional constructs that usually make the code easier to read.

<img src="Images/Chapters/0x06j/control-flow-flattening.png" width="100%" />

The image shows how control flow flattening alters code. See ["Obfuscating C++ programs via control flow flattening"](https://web.archive.org/web/20240414202600/http://ac.inf.elte.hu/Vol_030_2009/003.pdf) for more information.

#### Dead Code Injection

This technique makes the program's control flow more complex by injecting dead code into the program. Dead code is a stub of code that doesn't affect the original program's behavior but increases the overhead of the reverse engineering process.

#### String Encryption

Applications are often compiled with hardcoded keys, licences, tokens and endpoint URLs. By default, all of them are stored in plaintext in the data section of an application's binary. This technique encrypts these values and injects stubs of code into the program that will decrypt that data before it is used by the program.

#### Packing

[Packing](https://attack.mitre.org/techniques/T1027/002/) is a dynamic rewriting obfuscation technique which compresses or encrypts the original executable into data and dynamically recovers it during execution. Packing an executable changes the file signature in an attempt to avoid signature-based detection.

### Debugging and Tracing

In the traditional sense, debugging is the process of identifying and isolating problems in a program as part of the software development life cycle. The same tools used for debugging are valuable to reverse engineers even when identifying bugs is not the primary goal. Debuggers enable program suspension at any point during runtime, inspection of the process' internal state, and even register and memory modification. These abilities simplify program inspection.

_Debugging_ usually means interactive debugging sessions in which a debugger is attached to the running process. In contrast, _tracing_ refers to passive logging of information about the app's execution (such as API calls). Tracing can be done in several ways, including debugging APIs, function hooks, and Kernel tracing facilities. Again, we'll cover many of these techniques in the OS-specific "Reverse Engineering and Tampering" chapters.

## Advanced Techniques

For more complicated tasks, such as de-obfuscating heavily obfuscated binaries, you won't get far without automating certain parts of the analysis. For example, understanding and simplifying a complex control flow graph based on manual analysis in the disassembler would take you years (and most likely drive you mad long before you're done). Instead, you can augment your workflow with custom made tools. Fortunately, modern disassemblers come with scripting and extension APIs, and many useful extensions are available for popular disassemblers. There are also open source disassembling engines and binary analysis frameworks.

As always in hacking, the anything-goes rule applies: simply use whatever is most efficient. Every binary is different, and all reverse engineers have their own style. Often, the best way to achieve your goal is to combine approaches (such as emulator-based tracing and symbolic execution). To get started, pick a good disassembler and/or reverse engineering framework, then get comfortable with their particular features and extension APIs. Ultimately, the best way to get better is to get hands-on experience.

### Dynamic Binary Instrumentation

Another useful approach for native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is accomplished by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download.

The [Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html "Valgrind README") includes specific compilation instructions for Android.

### Emulation-based Dynamic Analysis

Emulation is an imitation of a certain computer platform or program being executed in different platform or within another program. The software or hardware performing this imitation is called an _emulator_. Emulators provide a much cheaper alternative to an actual device, where a user can manipulate it without worrying about damaging the device. There are multiple emulators available for Android, but for iOS there are practically no viable emulators available. iOS only has a simulator, shipped within Xcode.

The difference between a simulator and an emulator often causes confusion and leads to use of the two terms interchangeably, but in reality they are different, specially for the iOS use case. An emulator mimics both the software and hardware environment of a targeted platform. On the other hand, a simulator only mimics the software environment.

QEMU based emulators for Android take into consideration the RAM, CPU, battery performance etc (hardware components) while running an application, but in an iOS simulator this hardware component behaviour is not taken into consideration at all. The iOS simulator even lacks the implementation of the iOS kernel, as a result if an application is using syscalls it cannot be executed in this simulator.

In simple words, an emulator is a much closer imitation of the targeted platform, while a simulator mimics only a part of it.

Running an app in the emulator gives you powerful ways to monitor and manipulate its environment. For some reverse engineering tasks, especially those that require low-level instruction tracing, emulation is the best (or only) choice. Unfortunately, this type of analysis is only viable for Android, because no free or open source emulator exists for iOS (the iOS simulator is not an emulator, and apps compiled for an iOS device don't run on it). The only iOS emulator available is a commercial SaaS solution - @MASTG-TOOL-0108.

### Custom Tooling with Reverse Engineering Frameworks

Even though most professional GUI-based disassemblers feature scripting facilities and extensibility, they are simply not well-suited to solving particular problems. Reverse engineering frameworks allow you to perform and automate any kind of reversing task without depending on a heavy-weight GUI. Notably, most reversing frameworks are open source and/or available for free. Popular frameworks with support for mobile architectures include @MASTG-TOOL-0073 and @MASTG-TOOL-0030.

#### Example: Program Analysis with Symbolic/Concolic Execution

In the late 2000s, testing based on symbolic execution has become a popular way to identify security vulnerabilities. Symbolic "execution" actually refers to the process of representing possible paths through a program as formulas in first-order logic. Satisfiability Modulo Theories (SMT) solvers are used to check the satisfiability of these formulas and provide solutions, including concrete values of the variables needed to reach a certain point of execution on the path corresponding to the solved formula.

In simple words, symbolic execution is mathematically analyzing a program without executing it. During analysis, each unknown input is represented as a mathematical variable (a symbolic value), and hence all the operations performed on these variables are recorded as a tree of operations (aka. AST (abstract syntax tree), from compiler theory). These ASTs can be translated into so-called _constraints_ that will be interpreted by a SMT solver. In the end of this analysis, a final mathematical equation is obtained, in which the variables are the inputs whose values are not known. SMT solvers are special programs which solve these equations to give possible values for the input variables given a final state.

To illustrate this, imagine a function which takes one input (`x`) and multiplies it by the value of a second input (`y`). Finally, there is an _if_ condition which checks if the value calculated is greater than the value of an external variable(`z`), and returns "success" if true, else returns "fail". The equation for this operation will be `(x * y) > z`.

If we want the function to always return "success" (final state), we can tell the SMT solver to calculate the values for `x` and `y` (input variables) which satisfy the corresponding equation. As is the case for global variables, their value can be changed from outside this function, which may lead to different outputs whenever this function is executed. This adds to additional complexity in determining correct solution.

Internally SMT solvers use various equation solving techniques to generate solution for such equations. Some of the techniques are very advanced and their discussion is beyond the scope of this book.

In a real world situation, the functions are much more complex than the above example. The increased complexity of the functions can pose significant challenges for classical symbolic execution. Some of the challenges are summarised below:

- Loops and recursions in a program may lead to _infinite execution tree_.
- Multiple conditional branches or nested conditions may lead to _path explosion_.
- Complex equations generated by symbolic execution may not be solvable by SMT solvers because of their limitations.
- Program is using system calls, library calls or network events which cannot be handled by symbolic execution.

To overcome these challenges, typically, symbolic execution is combined with other techniques such as _dynamic execution_ (also called _concrete execution_) to mitigate the path explosion problem specific to classical symbolic execution. This combination of concrete (actual) and symbolic execution is referred to as _concolic execution_ (the name concolic stems from **conc**rete and symb**olic**), sometimes also called as _dynamic symbolic execution_.

To visualize this, in the above example, we can obtain the value of the external variable by performing further reverse engineering or by dynamically executing the program and feeding this information into our symbolic execution analysis. This extra information will reduce the complexity of our equations and may produce more accurate analysis results. Together with improved SMT solvers and current hardware speeds, concolic execution allows to explore paths in medium-size software modules (i.e., on the order of 10 KLOC).

In addition, symbolic execution also comes in handy for supporting de-obfuscation tasks, such as simplifying control flow graphs. For example, Jonathan Salwan and Romain Thomas have [shown how to reverse engineer VM-based software protections using Dynamic Symbolic Execution](https://drive.google.com/file/d/1EzuddBA61jEMy8XbjQKFF3jyoKwW7tLq/view?usp=sharing "Jonathan Salwan and Romain Thomas: How Triton can help to reverse virtual machine based software protections") [#salwan] (i.e., using a mix of actual execution traces, simulation, and symbolic execution).

In the Android section, you'll find a walkthrough for cracking a simple license check in an Android application using symbolic execution.

## References

- [#vadla] Ole André Vadla Ravnås, Anatomy of a code tracer - <https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8>
- [#salwan] Jonathan Salwan and Romain Thomas, How Triton can help to reverse virtual machine based software protections - <https://drive.google.com/file/d/1EzuddBA61jEMy8XbjQKFF3jyoKwW7tLq/view?usp=sharing>
