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

### White-box Testing

Verify the minifyEnabled is set to true in build.gradle (see below).

### Black-box Testing

To inspect the Java bytecode for metadata either use the dexdump tool that ships with the Android SDK or a decompiler.

TODO - show what obfuscated bytecode looks like

### Remediation

ProGuard should be used to strip unneeded debugging information from the Java bytecode. By default, ProGuard removes attributes that are useful for debugging, including line numbers, source file names and variable names. ProGuard is a free Java class file shrinker, optimizer, obfuscator, and preverifier. It is shipped with Android’s SDK tools. To activate shrinking for the release build, add the following to build.gradle:

~~~~ 
android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile(‘proguard-android.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
~~~~ 

### References

- [link to relevant how-tos, papers, etc.]
