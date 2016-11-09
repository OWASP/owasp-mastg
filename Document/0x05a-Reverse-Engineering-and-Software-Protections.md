## Tampering and Reverse Engineering

Mobile security testing requires at least basic reverse engineering skills for several reasons.

- In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

- Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and E2E encryption could prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

- Apps that implement software protections according to MASVS L3 or L4 should be resilient against reverse engineering. In this case, testing the reverse engineering defenses ("resiliency assessment") may be part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses. Advanced reverse engineering skills are required to perform this kind of test.

Reverse engineering is a creative process. The best software protections are based on original ideas, so there is no generic process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.

## Assessing Software Protections

The MASVS lists various kinds of software protections in the "V8 - Resiliency against Reverse Engineering" section.

Whether we’re talking about malware, banking apps, or mobile games: They all use similar anti-reversing strategies made from the same building blocks. This includes defenses against debuggers, tamper proofing of application files and memory, and verifying the integrity of the environment. The question is, how do we verify that the defenses, taken together, are “good enough” to provide the desired level of protection? In the MASVS and MSTG, we tackle this question by defining sets of criteria for obfuscations and functional (programmatic) defenses, as well as testing processes that can be used for manual verification.

On the highest level, we classify reverse engineering defenses into two categories: Functional defenses and obfuscations. Both are used in tandem to achieve resiliency. Table 1 gives an overview of the categories and sub-categories as they appear in the guide.

### 1. Functional defenses
*Prevent, or react to, actions of the reverse engineer*

Functions that aim to prevent likely actions of the reverse engineer. As an example, an app may an operating system API to prevent debuggers from attaching to the process. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached. 

### 2. Obfuscations
*Modify code and/or data to make it less comprehensible*

 Modifications applied during the build process to the source code, binary, intermediate representation of the code, or other elements such as data or executable headers. The goal is to transform the code and data so it becomes more difficult to comprehend for human adversaries while still performing the desired function. Obfuscating transformations change the representation of the code and data, but do not exhibit behavior of their own (i.e. they don’t actively interfere with the actions of the reverse engineer).

### Functional defense requirements

Functional defenses are programmatic features  that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached. When combined with obfuscation, multiple defenses add up to make the life of the reverse engineer as difficult as possible.

In the MASVS and MSTG, we define five defensive categories, each of which corresponds to a process used by reverse engineers (Figure 2). The MASVS defines the minimum amount of protection that must exist in each category.

![Reverse engineering processes](https://github.com/OWASP/owasp-mstg/blob/master/Document/images/reversing-processes.png "Reverse engineering processes")

For example, MASVS L2 requires an app to implement a simple form protection in the categories “environmental manipulation” and “debugging”. An app may pass as long as it implements any form of detection, no matter the specific implementation. MASVS  L3 ups the ante by adding requirements for all five categories:

- 8.6: "Verify that the app implements two or more functionally independent methods of root detection and responds to the presence of a rooted device either by alerting the user or terminating the app."
- 8.7: "Verify that the app implements multiple defenses that result in strong resiliency against debugging. All available means of debugging must be covered (e.g. JDWP and native)."
- 8.8: "Verify that the app detects and responds to tampering with executable files and critical data."
- 8.9: "Verify that the app detects the presence of widely used reverse engineering tools, such as code injection tools, hooking frameworks and debugging servers."
- 8.10: "Verify that the app detects whether it is run inside an emulator using any method, and responds by terminating or malfunctioning when an emulator is detected."
- 8.11: "Verify that the app detects modifications of process memory, including relocation table patches and injected code."

Basic requirements, such as 8.8 and 8.9, can be verified using either black-box or white-box testing (see the respective test cases for details). The requirement for *strong* resiliency in the debugging category (V8.7) will be discussed in the following sections.

#### Assessing the effectiveness of defenses

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

### Obfuscation requirements

![Obfuscation model](https://github.com/OWASP/owasp-mstg/blob/master/Document/images/obfuscation-model.png "Reverse engineering processes")

#### Tier 1: Strip meaningful information

Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.
For instance, class files generated with the standard Java compiler include the names of classes, methods and fields, making it trivial to reconstruct the source code. ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable. 
Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

#### Tier 2: Obfuscate control flow and data

The second type of obfuscations aims to hide the semantics of a computation by computing the same function in a more complicated way, or encoding sensitive data in ways that are not easily comprehensible. Provided that the adversary has no prior knowledge about the obfuscation parameters applied, these obfuscations increase the reverse engineering effort even for an adversary with full visibility of the execution trace. Obfuscation in this category have the following properties:

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

#### Tier 3: Inhibit reverse engineering processes and tools

The third category of transformations includes tricks that make static analysis more difficult, but do not transform the obfuscated computation per se. That is, the instructions that eventually compute the obfuscated function(s) remain more or less unchanged. Examples for this kind of transformations includes simple packing and encryption of large code blocks and manipulations of executable headers.
Transformations in this category have the following properties: 

- The size and performance penalty is neglibigle;
- De-obfuscation is relatively trivial, and can be accomplished with standard tools without scripting or customization.

In general, tier 3 obfuscations are a good way to achieve basic levels of reverse engineering protection without causing too much impact on size on performance. They can be used to deter less dedicated adversaries, and to add additional layers of resiliency once tier 1 and 2 obfuscations have been applied. 






