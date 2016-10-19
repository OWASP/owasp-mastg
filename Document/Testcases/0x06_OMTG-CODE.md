# Testing Code Quality

## Overview

[Describe what this chapter is about.]

## Test Cases

### OMTG-CODE-007: Testing for Secure Compiler Flags
Compilers such as CLANG and GCC support hardening options that add additional runtime security features and checks to the generated executables. While these hardening features don’t fix broken code, they do make exploitation of bugs such as buffer overflows more difficult, and should be activated as a defense-in-depth measure.

#### Detailed Guides

- [OMTG-CODE-007 Android](0x06a_OMTG-CODE_Android.md#OMTG-CODE-007)
- [OMTG-CODE-007 iOS](0x06b_OMTG-CODE_iOS.md#OMTG-CODE-007)

#### References

- OWASP MASVS : [Link to MASVS]
- CWE : [Link to CWE issue]
