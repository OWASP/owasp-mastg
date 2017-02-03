# Assessing the Quality of Software Protections

*TODO...  Goal: Define repeatable processes for assessing the effectiveness of software protections. For now this is just a copy/paste from some old writeups. Needs to be synced with [OWASP RE Prevention](https://www.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project), [Obfucation Metrics](https://github.com/b-mueller/obfuscation-metrics), [MASVS Reverse Engineering Resiliency](https://github.com/OWASP/owasp-masvs/blob/master/Document/0x15-V9-Resiliency_Against_Reverse_Engineering_Requirements.md).*

In prior chapters, you have learned basic reverse engineering techniques on both Android and iOS, and you've had a first glimpse at of the more advanced methods. We've shown examples for bypassing anti-tampering and de-obfuscating code. These skills are not only useful for regular security testing - with enough know-how and experience, you'll be able to give an assessment of how effective a particular set of anti-reversing measures is in practice. This process is called *resiliency testing*.

Whether we’re talking about malware, banking apps, or mobile games: They all use anti-reversing strategies made from the same building blocks. This includes defenses against debuggers, tamper proofing of application files and memory, and verifying the integrity of the environment. The question is, how do we verify that a given set of defenses (as a whole) is "good enough" to provide the desired level of protection? As it turns out, this is not an easy question to answer.

The first problem is that there is no one-size-fits-all. Client-side tampering protections are desirable in some cases, but are unnecessary, or even counter-productive, in others. In the worst case, software protections lead to a false sense of security and encourage bad programming practices, such as implementing server-side controls in the client. It is impossible to provide a generic set of resiliency controls that "just works" in every possible case. To work around this issue, we made modeling of client-side threats part of the requirements in MASVS-R: If one uses obfuscation and anti-tampering controls at all, they should be sure that they're doing it right, and without compromising the overall security architecture.

Another issue is that assessment methods and metrics for software protections are not widely available, and those that exist are often controversial. Currently, no form of software protection is backed by rigorous proof. What we can do however is present a comprehensive survey of the available (de-)obfuscation and (anti-)tampering research and a lot of practical experience.

Effective anti-reversing schemes combine a variety of tampering defenses and obfuscating transformations. Note that in the majority of cases, applying basic measures such as symbol stripping and root detection is sufficient.

## The Resiliency Testing Process

Resiliency testing usually follows the black-box approach. The process contains of the following high-level steps:

1. Assess whether a suitable and reasonable threat model exists, and the anti-reversing controls fit the threat model;
2. Assess the effectiveness of the defenses in countering using hybrid static/dynamic analysis.

### The Attacker's View

![High-level Process](/Document/Images/Chapters/0x07b/Binary_Attack_Overview_Process_Graph.png "Reverse engineering processes")

Attack Steps, from: https://www.owasp.org/index.php/Architectural_Principles_That_Prevent_Code_Modification_or_Reverse_Engineering

### Software Protections Model

We classify reverse engineering defenses into two categories: Tampering defenses and obfuscation. Both types of defenses are used in tandem to achieve resiliency. The following section contains an overview of the taxonomy used in the guide.

#### 1. Tampering Defenses

*Tampering Defenses* are programmatic functions that prevent, or react to, actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached. They can be further categorized into two modi operandi:

1. Preventive: Functions that aim to prevent likely actions of the reverse engineer. As an example, an app may an operating system API to prevent debuggers from attaching to the process.

2. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached.

Tampering defenses aim to hinder multiple processes used by reverse engineers, which we have grouped into 5 categories (Figure 2).

![Reverse engineering processes](/Document/Images/Chapters/0x07b/reversing-processes.png "Reverse engineering processes")

#### 2. Obfuscation

Obfuscation is the process of transforming code and data in ways that make it more difficult to comprehend, while preserving its original meaning or function. The simplest way of making code less comprehensible is stripping information that is meaningful to humans, such as function and variable names. A standard implementation of a cryptographic primitive can be replaced by a network of key-dependent lookup tables so the regular cryptographic key is not exposed in memory ("white-box cryptography"). Code can be into a secret byte-code language that is then run on an interpreter ("virtualization"). There's unlimited ways of encoding and transforming code and data!

*Obfuscating transformations* are modifications applied during the build process to the source code, binary, intermediate representation of the code, or other elements such as data or executable headers. We categorize them into two types:

1. Strip information
2. Obfuscate control flow and data

##### 1. Strip Meaningful Information

Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.

For instance, class files generated with the standard Java compiler include the names of classes, methods and fields, making it trivial to reconstruct the source code. ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable.

Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

##### 2. Obfuscate Control Flow and Data

Program code and data can be obfuscated in unlimited ways - and indeed, there is a rich body of informal and academic research dedicated to it.

An obfuscation scheme is effective if:

1. Robust transformations are applied appropriately to the code and/or data;
2. A sufficient increase in program complexity is achieved so that manual analysis becomes infeasible;
3. The transformations used are resilient against state-of-the-art de-obfuscation techniques.

Different types of obfuscating transformations vary in their impact on program complexity. The spectrum goes from simple *tricks*, such as packing and encryption of large code blocks and manipulations of executable headers, to more intricate forms of obfuscation like just-in-time compilation and virtualization that add significant complexity to parts of the code, data and execution trace.

###### Packing and Encryption

Simple transformations with little impact on program complexity can be used to defeat standard static analysis tools without causing too much size and performance penalties. The execution trace of the obfuscated function(s) remains more or less unchanged. De-obfuscation is relatively trivial, and can be accomplished with standard tools without scripting or customization.

###### Transforming Code and/or Data

Advanced methods aim to hide the semantics of a computation by computing the same function in a more complicated way, or encoding code and data in ways that are not easily comprehensible. Transformations in this category have the following properties:

- The size and performance penalty can be sizable (scales with the obfuscation settings)
- De-obfuscation requires advanced methods and/or custom tools

A simple example for this kind of obfuscations are opaque predicates. Opaque predicates are redundant code branches added to the program that always execute the same way, which is known a priori to the programmer but not to the analyzer. For example, a statement such as if (1 + 1) = 1 always evaluates to false, and thus always result in a jump to the same location. Opaque predicates can be constructed in ways that make them difficult to identify and remove in static analysis.

Some types of obfuscation that fall into this category are:

- Pattern-based obfuscation, when instructions are replaced with more complicated instruction sequences
- Control flow obfuscation
- Control flow flattening
- Function Inlining
- Data encoding and reordering
- Variable splitting
- Virtualization
- White-box cryptography

### Assessing the Threat Model and Architecture

(... TODO ...)

#### Assessing the Quality of Functional Defenses

For real-world apps, automated static/dynamic analysis is insufficient to prove security of a program. Manual verification by an experienced tester is still the only reliable way to achieve security.

### Assessing Obfuscations
