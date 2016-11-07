# Testing Processes and Techniques

## Black-box Testing

## White-box Testing

## Static Analysis

## Dynamic Analysis

## Tampering and Reverse Engineering



## Assessing Software Protections

Whether we’re talking about malware, banking apps, or mobile games: They all use similar anti-reversing strategies made from the same building blocks. This includes defenses against debuggers, tamper proofing of application files and memory, and verifying the integrity of the environment. The question is, how do we verify that the defenses, taken together, are “good enough” to provide the desired level of protection? In the MASVS and MSTG, we tackle this question by defining sets of criteria for obfuscations and functional (programmatic) defenses, as well as testing processes that can be used for manual verification.

On the highest level, we classify reverse engineering defenses into two categories: Functional defenses and obfuscations. Both are used in tandem to achieve resiliency. Table 1 gives an overview of the categories and sub-categories as they appear in the guide.

| Functional Defenses | Obfuscations  |
| -----------------   |--------------|
| *Prevent, or react to, actions of the reverse engineer* | *Modify code and/or data to make it less comprehensible* |
| Preventive: Functions that aim to prevent likely actions of the reverse engineer. As an example, an app may an operating system API to prevent debuggers from attaching to the process. Reactive: Features that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached.   | Modifications that are usually applied during the build process to the source code, binary, intermediate representation of the code, or other elements such as data or executable headers. The goal is to transform the code and data so it becomes more difficult to comprehend for human adversaries while still performing the desired function. Obfuscating transformations change the representation of the code and data, but do not exhibit behavior of their own (i.e. they don’t actively interfere with the actions of the reverse engineer). |
| 1. Immediate response| 1. Strip meaningful information|
| 2. Delayed response (stealth)| 2. Increase complexity|
||3. Inhibit reverse engineering processes and tools|

### Testing Functional Defenses

Functional defenses are programmatic features  that aim to detect, and respond to, tools or actions of the reverse engineer. For example, an app could terminate when it suspects being run in an emulator, or change its behavior in some way a debugger is attached. When combined with obfuscation, multiple defenses add up to make the life of the reverse engineer as difficult as possible.

In the MASVS and MSTG, we define five defensive categories, each of which corresponds to a process used by reverse engineers (Figure 2). The MASVS defines the minimum amount of protection that must exist in each category.

![Reverse engineering processes](https://github.com/OWASP/owasp-mstg/blob/master/Document/images/reversing-processes.png "Reverse engineering processes")

### Testing Obfuscation

1. Stripping

   Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.
   Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

2. Increase Complexity

   The second type of obfuscations aims to hide the semantics of a computation by embedding it into a more complex computation. Put another way, these transformations increase the absolute amount of high-variability information in the code and data representing a certain functionality, thereby increasing the amount of information an adversary must process to understand the semantics of the code. Provided that the adversary has no prior knowledge about the obfuscation parameters applied, these obfuscations increase the reverse engineering effort even for an adversary with full visibility of all operations executed by the CPU.

3. TODO

Increase Complexity
