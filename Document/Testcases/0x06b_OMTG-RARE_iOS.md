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

## <a name="OMTG-RARE-006"></a>OMTG-RARE-006: Test Advanced Jailbreak / Root Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-007"></a>OMTG-RARE-007: Test Advanced Debugging Defenses

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-008"></a>OMTG-RARE-008: Test File Tampering Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-009"></a>OMTG-RARE-009: Test Detection of Reverse Engineering Tools

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-010"></a>OMTG-RARE-010: Test Basic Emulator Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-011"></a>OMTG-RARE-011: Test Memory Tampering Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-012"></a>OMTG-RARE-012: Test Variability of Tampering Responses

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-013"></a>OMTG-RARE-013: Test Binary Encryption

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-014"></a>OMTG-RARE-014: Test Device Binding

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-015"></a>OMTG-RARE-015: Test Advanced Jailbreak / Root Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-016"></a>OMTG-RARE-016: Test Advanced Emulator Detection

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-017"></a>OMTG-RARE-017: Test Integration of SE and/or TEE

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]

## <a name="OMTG-RARE-018"></a>OMTG-RARE-018: Test Advanced Obfuscation

### White-box Testing


### Black-box Testing


### References

- [link to relevant how-tos, papers, etc.]
