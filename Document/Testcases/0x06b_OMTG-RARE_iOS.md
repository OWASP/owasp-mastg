## <a name="OMTG-RARE-001"></a>OMTG-RARE-001: Test for Debugging Symbols in Binaries

### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

### Black-box Testing

Symbols  are usually stripped during the build process, so you need the compiled bytecode and libraries to verify whether the any unnecessary metadata has been discarded. For native binaries, use a standard tool like nm or objdump to inspect the symbol table. For example:

~~~~ 
berndt@osboxes:~/ $ objdumpApplication Security Verification Standard -t my_library.so
my_library.so:     file format elf32-little

SYMBOL TABLE:
no symbols
~~~~ 

Alternatively, open the file in your favorite disassembler and look for debugging symbols. For native libraries, it should be checked that the names of exports don’t give away the location of sensitive functions. 

### Remediation

[Describe the best practices that developers should follow to prevent this issue]

### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-002"></a>OMTG-RARE-002:  Test for Meaningful Identifiers in Java Bytecode

This test case is not applicable on iOS.

## <a name="OMTG-RARE-003"></a>OMTG-RARE-003: Test Jailbreak / Root Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-004"></a>OMTG-RARE-004: Test Verification of Installation Source

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-005"></a>OMTG-RARE-005: Test Simple Debugger Detection / Prevention

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]
