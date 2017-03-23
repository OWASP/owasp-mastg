# Assessing Anti-Reverse Engineering Schemes

In practice, you'll find that many mobile apps implement defenses aiming to make reverse engineering and tampering more difficult. There are several reason why the developers choose to do this: For example, the intention could be to add some protection to locally saved data, to make it more difficult to steal the source code and IP, or to prevent users from tampering with the behaviour of the app. As a security tester, being asked to give an assessment of the effectiveness of such defenses is becoming more and more common.

A sizable percentage of security experts will immediately interject: "But anti-reversing defenses can be bypassed! They don't add anything but security-by-obscurity!". And they're right: Ultimately, software-based defenses can always be defeated, and they should **never** be used in place of solid security controls. The point of this kind of defenses is indeed to add certain amount of obscurity - enough to deter and delay particular groups of adversaries from achieving certain goals. *Resiliency testing* is the process of verifying that the defenses implemented have the desired effect.

Mobile app anti-reversing schemes are all made from similar building blocks. On the one hand, apps implement defenses against debuggers, tamper proofing of application files and memory, and verifying the integrity of the environment. On the other hand obfuscation is employed to make code and data incomprehensible. How can you verify that a given set of defenses (as a whole) is "good enough" to provide an appropriate level of protection? As it turns out, this is not an easy question to answer.

Firstly, there is no one-size-fits-all. Client-side protections are desirable in some cases, but unnecessary or even counter-productive in others. In the worst case, software protections cause a false sense of security and encourage bad programming practices, such as implementing security controls on the client that would better be located on the server. It is impossible to provide a generic set of resiliency controls that "just works" in every possible case. For this reason, proper modeling of client-side threats is a necessary prerequisite before any form of software protections are implemented.

In the OWASP Mobile Verification Standard and Testing Guide, anti-reversing controls are (for the most part) treated separately from security controls. This has several reasons: For one, we don't think that a *lack of anti-reversing controls* should ever be reported as a *vulnerability*. Also, assessing anti-reversing defenses requires an extended skillset: The tester must be able to handle advanced anti-reversing tricks and obfuscation techniques. Traditionally, this skillset is associated with malware reseachers - penetration testers often don't have this kind of know-how.  

Resiliency testing can be performed in the context of a regular mobile app security test, or stand-alone to verify the effectiveness of a software protection scheme. The process consists of the following high-level steps:

1. Assess whether a suitable and reasonable threat model exists, and the anti-reversing controls fit the threat model;
2. Assess the effectiveness of the defenses in countering the identified threats using hybrid static/dynamic analysis*.

* In other words, play the role of the reverse engineer, and break the defenses.

## Assessing the Threat Model and Software Protection Architecture

The software protection scheme must be designed to protect against clearly defined threats - otherwise it is no more than a random collection of anti-debugging tricks. The OWASP Reverse Engineering and Code Modification Prevention Project [2] lists the following potential threats associated with reverse engineering and tampering:

- Spoofing Identity - Attackers may attempt to modify the mobile application code on a victim’s device to force the application to transmit a user’s authentication credentials (username and password) to a third party malicious site. Hence, the attacker can masquerade as the user in future transactions;

- Tampering - Attackers may wish to alter higher-level business logic embedded within the application to gain some additional value for free. For instance, an attacker may alter digital rights management code embedded in a mobile application to attain digital assets like music for free;

- Repudiation - Attackers may disable logging or auditing controls embedded within the mobile application to prevent an organization from verifying that the user performed particular transactions;

- Information Disclosure - Attackers may modify a mobile application to disclose highly sensitive assets contained within the mobile application. Assets of interest include: digital keys, certificates, credentials, metadata, and proprietary algorithms;

- Denial of Service - Attackers may alter a mobile device application and force it to periodically crash or permanently disable itself to prevent the user from accessing online services through their device;

- Elevation of Privilege - Attackers may modify a mobile application and redistribute it in a repackaged form to perform actions that are outside of the scope of what the user should be able to do with the app.

## Anti-Tampering Requirements in the MASVS

Defining software protection standards is a self-defeating endeavor. Effective software protection schemes depend on a certain amount of originality and secrecy. The more everyone follows the same exact standards, the more ineffectice they become in deterring reverse engineers: Soon enough, there'll be a generic tool available to bypass the particular standard defenses.

Instead of specifying implementation details, the category "Resiliency Against Reverse Engineering" of the MASVS (MASVS-R) focuses on the following questions:

**Does the app defend comprehensively against processes and tools used by reverse engineers?**

Programmatic defenses aim to hinder various processes used by reverse engineers, which we have grouped into five categories. To fully adhere to MASVS-R, an app must implement (sometimes multiple) defenses in each category.

![Reverse engineering processes](Images/Chapters/0x04/reversing-processes.png "Reverse engineering processes")

** Do the defense act together in the right ways so that an effective protection scheme? **

-- TODO [Just copy/paste from MASVS - describe in detail] --

The app implements multiple different responses to tampering, debugging and emulation, including stealthy responses that don't simply terminate the app. All executable files and libraries belonging to the app are either encrypted on the file level and/or important code and data segments inside the executables are encrypted or packed. Trivial static analysis should not reveal important code or data. Obfuscating transformations and functional defenses are interdependent and well-integrated throughout the app.

## Testing Programmatic Defenses

Software protection schemes incorporate a variety of functions that prevent, or react to, actions of the reverse engineer. For example, an app could terminate when it suspects being run on a rooted device or on an emulator. These *programmatic defenses* can be further categorized into two modi operandi:

1. Preventive: Functions that aim to *prevent* anticipated actions of the reverse engineer. As an example, an app may use an operating system API to prevent debuggers from attaching.

2. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way if a debugger is detected.

For a protection scheme to be considered effective, it must incorporate defenses against all five processes. Furthermore, to achieve overall robustness, the defenses in each category must be comprised of multiple mechanisms (e.g. multiple functionally independent means of anti-debugging on different API layers). *Resiliency testing* is the process of verifying the effectiveness of those mechanisms.

-- TODO [What does it mean for programmatic defenses to be effective?] --

### Quality Criteria

"More is better" is not always a great motto in real life but it does apply to software protections. Employing multiple defenses simultaneously makes it difficult for the adversary to get a foothold for starting the analysis. They may find that the binary code is encrypted and doesn’t load in their favorite disassembler. Multiple layers of debugging defenses prevent her from easily dumping the decrypted code. Patching the binary code is difficult due to its encrypted nature, and because it triggers additional integrity checks.

#### Response Type

Less is better in terms of information given to the adversary. The most effective defensive features are designed to respond in stealth mode: The attacker is left completely unaware that a defensive mechanism has been triggered. 

- Feedback: When the anti-tampering response is triggered, an error message is displayed to the user or written to a log file. The adversary can immediately discern the nature of the defensive feature as well as the time at which the mechanism was triggered.
- Indiscernible: The defense mechanism terminates the app without providing any error details and without logging the reason for the termination. The adversary does not learn information about the nature of the defensive feature, but can discern the approximate time at which the feature was triggered.
- Stealth: The anti-tampering feature either does not visibly respond at all to the detected tampering, or the response happens with a significant delay. For example, the mechanism could corrupt a pointer which leads to a malfunction at a much later point in time.

#### API Layer

Lower-level calls are more difficult to defeat than higher level calls. 

- System Library: The feature relies on public library functions or methods.
- Kernel: The anti-reversing feature calls directly into the kernel. 
- Self-contained: The feature does not require any library or system calls to work.

#### Uniqueness

The more original the anti-reversing trick, the less likely the adversary has seen it all before. 

- Standard API: The feature relies on APIs that are specifically meant to prevent reverse engineering. It can be bypassed easily using generic tools.
- Published: A well-documented and commonly used technique is used. It can be bypassed by using widely available tools with a moderate amount of customization.
- Proprietary: The feature is not commonly found in published anti-reverse-engineering resources for the target operating system, or a known technique has been sufficiently extended / customized to cause significant effort for the reverse engineer. 

#### Parallelism

Debugging and disabling a mechanism becomes more difficult when multiple threats or processes are involved.

- Single thread 
- Multiple threads or processes

## Testing Obfuscation Schemes

Obfuscation is the process of transforming code and data in ways that make it more difficult to comprehend, while preserving its original meaning or function. Think about translating an English sentence into an French one that says the same thing (or pick a different language if you speak French - you get the point).

The simplest way of making code less comprehensible is stripping information that is meaningful to humans, such as function and variable names. Many more intricate ways have been invented by software authors - especially those writing malware and DRM systems - over the past decades, from encrypting portions of code and data, to self-modifying and self-compiling code.

A standard implementation of a cryptographic primitive can be replaced by a network of key-dependent lookup tables so the original cryptographic key is not exposed in memory ("white-box cryptography"). Code can be into a secret byte-code language that is then run on an interpreter ("virtualization"). There are infinite ways of encoding and transforming code and data!

Things become complicated when it comes to pinpointing an exact academical definition. In an often cited paper, Barak et. al describe the black-box model of obfuscation. The black-box model considers a program P' obfuscated if any property that can be learned from P' can also be obtained by a simulator with only oracle access to P. In other words, P’ does not reveal anything except its input-output behavior. The authors also show that obfuscation is impossible given their own definition by constructing an un-obfuscable family of programs (8).

Does this mean that obfuscation is impossible? Well, it depends on what you obfuscate and how you define obfuscation. Barack’s result only shows that *some* programs cannot be obfuscated - but only if we use a very strong definition of obfuscation. Intuitively, most of us know from experience that code can have differing amounts of intelligibility and that understanding the code becomes harder as code complexity increases. Often enough, this happens unintentionally, but we can also observe that implementations of obfuscators exist and are more or less successfully used in practice (9).

### Obfuscation Types

*Obfuscating transformations* are modifications applied during the build process to the source code, binary, intermediate representation of the code, or other elements such as data or executable headers. We categorize them into two types:

1. Strip information
2. Obfuscate control flow and data

**1. Strip Meaningful Information**

Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.

For instance, class files generated with the standard Java compiler include the names of classes, methods and fields, making it trivial to reconstruct the source code. ELF and Mach-O binaries have a symbol table that contains debugging information, including the names of functions, global variables and types used in the executable.

Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

**2. Obfuscate Control Flow and Data**

Program code and data can be obfuscated in unlimited ways - and indeed, there is a rich body of informal and academic research dedicated to it.

*Packing and Encryption*

Simple transformations with little impact on program complexity can be used to defeat standard static analysis tools without causing too much size and performance penalties. The execution trace of the obfuscated function(s) remains more or less unchanged. De-obfuscation is relatively trivial, and can be accomplished with standard tools without scripting or customization.

*Transforming Code and/or Data*

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

### Obfuscation Requirements in the MASVS

-- TODO [Describe Obfuscation Requirements in the MASVS] --

### Obfuscation Effectiveness

An obfuscation scheme is effective if:

1. Robust transformations are applied appropriately to the code and/or data;
2. A sufficient increase in program complexity is achieved so that manual analysis becomes infeasible;
3. The transformations used are resilient against state-of-the-art de-obfuscation techniques.

Different types of obfuscating transformations vary in their impact on program complexity. The spectrum goes from simple *tricks*, such as packing and encryption of large code blocks and manipulations of executable headers, to more intricate forms of obfuscation like just-in-time compilation and virtualization that add significant complexity to parts of the code, data and execution trace.
