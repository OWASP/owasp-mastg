# Assessing the Quality of Software Protections

Whether we’re talking about malware, banking apps, or mobile games: They all use anti-reversing strategies made from the same building blocks. This includes defenses against debuggers, tamper proofing of application files and memory, and verifying the integrity of the environment. The question is, how do we verify that a given set of defenses (as a whole) is "good enough" to provide the desired level of protection? As it turns out, this is not an easy question to answer.

The first problem is that there is no one-size-fits-all. Client-side tampering protections are desirable in some cases, but are unnecessary, or even counter-productive, in others. In the worst case, software protections lead to a false sense of security and encourage bad programming practices, such as implementing server-side controls in the client. It is impossible to provide a generic set of resiliency controls that "just works" in every possible case. To work around this issue, we made modeling of client-side threats part of the requirements in MASVS-R: If one uses obfuscation and anti-tampering controls at all, they should be sure that they're doing it right, and without compromising the overall security architecture.

Another issue is that assessment methods and metrics for software protections are not widely available, and those that exist are often controversial. Currently, no form of software protection have been proven (in the scientific sense) to be effective. What we can do however is present a comprehensive survey of the available (de-)obfuscation and (anti-)tampering research, throw in some practical experience and common sense, and base our standard on that.

In this chapter, we outline a process called *resiliency testing*. Resiliency testing is analogous and complementary to security testing, with a few important differences. (... TODO ...)

1. Assess whether a suitable and reasonable threat model exists, and the anti-reversing controls fit the threat model;
2. Assess the effectiveness of the defenses in countering using hybrid static/dynamic analysis.


## Testing Software Protection Schemes


### The Attacker's View

![High-level Process](/Document/Images/Chapters/0x07b/Binary_Attack_Overview_Process_Graph.png "Reverse engineering processes")

Attack Steps, from: https://www.owasp.org/index.php/Architectural_Principles_That_Prevent_Code_Modification_or_Reverse_Engineering


### Software Protections Model

On the highest level, we classify reverse engineering defenses into two categories: Functional defenses and obfuscations. Both are used in tandem to achieve resiliency. Table 1 gives an overview of the categories and sub-categories as they appear in the guide.

#### 1. Functional Defenses

*Functional defenses* are program functions that prevent, or react to, actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached. They can be further categorized into two modi operandi:

1. Preventive: Functions that aim to prevent likely actions of the reverse engineer. As an example, an app may an operating system API to prevent debuggers from attaching to the process.

2. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached.

We define five defensive categories, each of which corresponds to a process used by reverse engineers (Figure 2).

![Reverse engineering processes](/Document/Images/Chapters/0x07b/reversing-processes.png "Reverse engineering processes")

#### 2. Obfuscating Transformations

*Obfuscating transformations* are modifications applied during the build process to the source code, binary, intermediate representation of the code, or other elements such as data or executable headers. The goal is to transform the code and data so it becomes more difficult to comprehend for human adversaries while still performing the desired function. Obfuscating transformations are further categorized into two types:

1. Strip information
2. Obfuscate control flow and data

Effective anti-reversing schemes combine a variety of functional defenses and obfuscating transformations. Note that in the majority of cases, applying basic measures such as symbol stripping and root detection is sufficient. In some cases however it is desirable to increase resiliency against reverse engineering - in these cases, advanced functional defenses and obfuscating transformations may be added.

##### 1. Strip Meaningful Information

Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.

For instance, class files generated with the standard Java compiler include the names of classes, methods and fields, making it trivial to reconstruct the source code. ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable.
Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

##### 2. Obfuscate Control Flow and Data

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


### Assessing the Threat Model and Architecture

(... TODO ...)

#### Assessing the Quality of Functional Defenses

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

### Assessing Obfuscations
