# Testing Processes and Techniques

## Black-box Testing

## White-box Testing

## Static Analysis

## Dynamic Analysis

## Tampering and Reverse Engineering

## Assessing Software Protections

On the highest level we classify reverse engineering defenses into two categories: Functional defenses and obfuscations. Both are used in tandem to achieve resiliency. Table 1 gives an overview of the categories and sub-categories as they are used in the guide.

(table 1)


### Testing Functional Defenses



### Testing Obfuscation



1. Stripping

   Compiled programs often retain explanative information that is helpful for the reverse engineer, but isn’t actually needed for the program to run. Debugging symbols that map machine code or byte code to line numbers, function names and variable names are an obvious example.
   Stripping this information makes a compiled program less intelligible while fully preserving its functionality. Possible methods include removing tables with debugging symbols, or renaming functions and variables to random character combinations instead of meaningful names. This process sometimes reduces the size of the compiled program and doesn’t affect its runtime behavior.

2. Increase Complexity

   The second type of obfuscations aims to hide the semantics of a computation by embedding it into a more complex computation. Put another way, these transformations increase the absolute amount of high-variability information in the code and data representing a certain functionality, thereby increasing the amount of information an adversary must process to understand the semantics of the code. Provided that the adversary has no prior knowledge about the obfuscation parameters applied, these obfuscations increase the reverse engineering effort even for an adversary with full visibility of all operations executed by the CPU.
   
3. TODO

Increase Complexity
