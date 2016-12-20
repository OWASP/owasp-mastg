# Assessing the Quality of Software Protections

This chapter covers defense-in-depth measures that are recommended for apps that process, or give access to, sensitive data or functionality. Lack of any of these controls does not cause a vulnerability - instead, they are meant to increase the app's resiliency against reverse engineering, making it more difficult for adversaries to gain an understanding of the app's internals or extract data from the app.

## Testing Software Protections

Whether we’re talking about malware, banking apps, or mobile games: They all use anti-reversing strategies made from the same building blocks. This includes defenses against debuggers, tamper proofing of application files and memory, and verifying the integrity of the environment. The question is, how do we verify that the defenses, taken together, are “good enough” to provide the desired level of protection in a given scenario? In the MASVS and MSTG, we tackle this question by defining sets of criteria for obfuscations and functional (programmatic) defenses, as well as testing processes that can be used for manual verification.

### Software Protections Model

On the highest level, we classify reverse engineering defenses into two categories: Functional defenses and obfuscations. Both are used in tandem to achieve resiliency. Table 1 gives an overview of the categories and sub-categories as they appear in the guide.

#### 1. Functional defenses

*Functional defenses* are program functions that prevent, or react to, actions of the reverse engineer. They can be further categorized into two modi operandi:

1. Preventive: Functions that aim to prevent likely actions of the reverse engineer. As an example, an app may an operating system API to prevent debuggers from attaching to the process.

2. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached.

#### 2. Obfuscating Transformations

*Obfuscating transformations* are modifications applied during the build process to the source code, binary, intermediate representation of the code, or other elements such as data or executable headers. The goal is to transform the code and data so it becomes more difficult to comprehend for human adversaries while still performing the desired function. Obfuscating transformations are further categorized into two types:

1. Strip information
2. Obfuscate control flow and data

Effective anti-reversing schemes combine a variety of functional defenses and obfuscating transformations. Note that in the majority of cases, applying basic measures such as symbol stripping and root detection is sufficient (MASVS L2). In some cases however it is desirable to increase resiliency against reverse engineering - in these cases, advanced functional defenses and obfuscating transformations may be added (MASVS L3-L4).

### Functional Defense Requirements

Functional defenses are programmatic features  that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached. When combined with obfuscation, multiple defenses add up to make the life of the reverse engineer as difficult as possible.

In the MASVS and MSTG, we define five defensive categories, each of which corresponds to a process used by reverse engineers (Figure 2). The MASVS defines the minimum amount of protection that must exist in each category.

![Reverse engineering processes](/Document/Images/Chapters/0x07b/reversing-processes.png "Reverse engineering processes")

For example, MASVS L2 requires an app to implement a simple form protection in the categories “environmental manipulation” and “debugging”. An app may pass as long as it implements any form of detection, no matter the specific implementation. MASVS  L3 ups the ante by adding requirements for all five categories:

- 8.6: "Verify that the app implements two or more functionally independent methods of root detection and responds to the presence of a rooted device either by alerting the user or terminating the app."
- 8.7: "Verify that the app implements multiple defenses that result in strong resiliency against debugging. All available means of debugging must be covered (e.g. JDWP and native)."
- 8.8: "Verify that the app detects and responds to tampering with executable files and critical data."
- 8.9: "Verify that the app detects the presence of widely used reverse engineering tools, such as code injection tools, hooking frameworks and debugging servers."
- 8.10: "Verify that the app detects whether it is run inside an emulator using any method, and responds by terminating or malfunctioning when an emulator is detected."
- 8.11: "Verify that the app detects modifications of process memory, including relocation table patches and injected code."

Basic requirements, such as 8.8 and 8.9, can be verified using either black-box or white-box testing (see the respective test cases for details). The requirement for *strong* resiliency in the debugging category (V8.7) will be discussed in the following sections.

#### Testing Functional Defenses

The simple, score-based system described below is based practical experience and feedback from malware analysts and reverse engineers. For a given defensive category, each defense in the category is scored individually, and the scores are then added to obtain a final score. A “defense” in this context is a function, or group of functions, with a common modus operandi and goal.

Each individual defensive function is assessed on three properties:
-	Uniqueness: 1 – 3 points
-	API Layer: Up to 2 bonus points
-	Parallelism: Up to 2 bonus points

Table 2 explains the scoring criteria in detail.

|               | **Uniqueness**    | **API Layer**   | **Parallelism** |
| ------------- |:-------------:| -----:| ------------------|
| **Rationale**     | *Lower-level calls are more difficult to defeat than higher level calls.*  | *The more original and/or customized the anti-reversing trick, the less likely the adversary has seen it all before*.  |  *Debugging and disabling a mechanism becomes more difficult when multiple threats or processes are involved.*  |
| **Level 1**  | Standard API (1 point): The feature relies on APIs that are specifically meant to hinder reverse engineering. It can be bypassed easily using generic |   System Library (1 point): The feature relies on public library functions or methods.| Single thread |
| **Level 2** | Published (2 points): A well-documented and commonly used technique is used. It can be bypassed by using widely available tools with a moderate amount of customization. |    Kernel (1 bonus point): The anti-reversing feature calls directly into the kernel.  | N/A  |
| **Level 3** | Proprietary (3 points): The feature is not commonly found in published anti-reverse-engineering resources for the target operating system, or a known technique has been sufficiently extended / customized to cause significant effort for the reverse engineer     |  Self-contained (2 bonus points): The feature does not require any library or system calls to work. | Multiple threads or processes (2 bonus points) |

### Obfuscation Requirements

#### 1. Strip meaningful information

Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.

For instance, class files generated with the standard Java compiler include the names of classes, methods and fields, making it trivial to reconstruct the source code. ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable.
Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

#### 2. Obfuscate control flow and data

Program code and data can be transformed in unlimited ways - and indeed, the field of control flow and data obfuscation is highly diverse, with a large amount of research dedicated to both obfuscation and de-obfuscation. Deriving general rules as to what is considered *strong* obfuscation is not an easy task. In the MSTG model, we take a two-fold approach:

1. Apply complexity and distance metrics to quantify the overall impact of the obfuscating transformations;
2. Define domain-specific criteria based on the state-of-the-art in obfuscation research.

Our working hypothesis that reverse engineering effort generally increases with program complexity, as long as no well-known automated de-obfuscation techniques exits. Note that it is unrealistic to assume that strong resiliency can be proven in a scientifically sound way for a complex application. Our goal is to provide guidelines, processes and metrics that enable a human tester to provide a reasonable assessment of whether strong resiliency has been achieved. Ideally, experimental data can then be used to verify (or refute) the proposed metrics. The situation is analogue to "regular" security testing: For real-world apps, automated static/dynamic analysis is insufficient to prove security of a program. Manual verification by an experienced tester is still the only reliable way to achieve security.

Different types of obfuscating transformations vary in their impact on program complexity. In general, there is a gradient from simple *tricks*, such as packing and encryption of large code blocks and manipulations of executable headers, to more "intricate" forms of obfuscation that add significant complexity to parts of the code, data and execution trace.

Simple transformations can be used to defeat standard static analysis tools without causing too much impact on size on performance. The execution trace of the obfuscated function(s) remains more or less unchanged. De-obfuscation is relatively trivial, and can be accomplished with standard tools without scripting or customization.

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
