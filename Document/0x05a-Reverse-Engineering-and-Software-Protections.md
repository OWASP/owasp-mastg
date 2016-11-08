## Tampering and Reverse Engineering



## Assessing Software Protections

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

(TODO)

### Obfuscation requirements

![Obfuscation model](https://github.com/OWASP/owasp-mstg/blob/master/Document/images/obfuscation-model.png "Reverse engineering processes")

#### Tier 1: Strip Meaningful Information

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

#### Tier 3: Inhibit Reverse Engineering Processes and Tools

The third category of transformations includes tricks that make static analysis more difficult, but do not transform the obfuscated computation per se. That is, the instructions that eventually compute the obfuscated function(s) remain more or less unchanged. Examples for this kind of transformations includes simple packing and encryption of large code blocks and manipulations of executable headers.
In contrast to “type 2” obfuscations, transformations in this category have the following properties: 

- The size and performance penalty is neglibigle;
- De-obfuscation is relatively trivial, and can be accomplished with standard tools without scripting or customization.

In general, type 3 obfuscations are a good way to achieve basic levels of reverse engineering protection without causing too much impact on size on performance. They can be used to deter less dedicated adversaries, and to add additional layers of resiliency once type 1 and 2 obfuscations have been applied. 

