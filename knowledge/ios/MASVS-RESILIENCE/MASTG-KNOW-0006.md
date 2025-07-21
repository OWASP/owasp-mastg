---
masvs_category: MASVS-RESILIENCE
platform: ios
title: Obfuscation
---

The chapter ["Mobile App Tampering and Reverse Engineering"](0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) introduces several well-known obfuscation techniques that can be used in mobile apps in general.

## Name Obfuscation

The standard compiler generates binary symbols based on class and function names from the source code. Therefore, if no obfuscation was applied, symbol names remain meaningful and can be easily read straight from the app binary. For instance, a function which detects a jailbreak can be located by searching for relevant keywords (e.g. "jailbreak"). The listing below shows the disassembled function `JailbreakDetectionViewController.jailbreakTest4Tapped` from the @MASTG-APP-0024.

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

## Instruction Substitution

This technique replaces standard binary operators like addition or subtraction with more complex representations. For example an addition `x = a + b` can be represented as `x = -(-a) - (-b)`. However, using the same replacement representation could be easily reversed, so it is recommended to add multiple substitution techniques for a single case and introduce a random factor. This technique is vulnerable to deobfuscation, but depending on the complexity and depth of the substitutions, applying it can still be time consuming.

## Control Flow Flattening

Control flow flattening replaces original code with a more complex representation. The transformation breaks the body of a function into basic blocks and puts them all inside a single infinite loop with a switch statement that controls the program flow. This makes the program flow significantly harder to follow because it removes the natural conditional constructs that usually make the code easier to read.

<img src="Images/Chapters/0x06j/control-flow-flattening.png" width="600px">

The image shows how control flow flattening alters code. See ["Obfuscating C++ programs via control flow flattening"](https://web.archive.org/web/20240414202600/http://ac.inf.elte.hu/Vol_030_2009/003.pdf) for more information.

## Dead Code Injection

This technique makes the program's control flow more complex by injecting dead code into the program. Dead code is a stub of code that doesn't affect the original program's behaviour but increases the overhead for the reverse engineering process.

## String Encryption

Applications are often compiled with hardcoded keys, licences, tokens and endpoint URLs. By default, all of them are stored in plaintext in the data section of an application's binary. This technique encrypts these values and injects stubs of code into the program that will decrypt that data before it is used by the program.

## Recommended Tools

- @MASTG-TOOL-0068 can be used to perform name obfuscation. It reads the source code of the Xcode project and replaces all names of classes, methods and fields with random values before the compiler is used.
- [obfuscator-llvm](https://github.com/obfuscator-llvm) operates on the Intermediate Representation (IR) instead of the source code. It can be used for symbol obfuscation, string encryption and control flow flattening. Since it's based on IR, it can hide out significantly more information about the application as compared to SwiftShield.

Learn more about iOS obfuscation techniques in the paper ["Protecting Million-User iOS Apps with Obfuscation: Motivations, Pitfalls, and Experience"](https://faculty.ist.psu.edu/wu/papers/obf-ii.pdf "Paper - Protecting Million-User iOS Apps with Obfuscation: Motivations, Pitfalls, and Experience").
