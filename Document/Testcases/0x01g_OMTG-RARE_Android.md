### <a name="OMTG-RARE-001"></a>OMTG-RARE-001: Test for Debugging Symbols in Binaries

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

(Describe how to assess this with access to the source code and build configuration)

#### Black-box Testing

Symbols  are usually stripped during the build process, so you need the compiled bytecode and libraries to verify whether the any unnecessary metadata has been discarded. For native binaries, use a standard tool like nm or objdump to inspect the symbol table. For example:

~~~~
berndt@osboxes:~/ $ objdump -t my_library.so
my_library.so:     file format elf32-little

SYMBOL TABLE:
no symbols
~~~~

Alternatively, open the file in your favorite disassembler and look for debugging symbols. For native libraries, it should be checked that the names of exports don’t give away the location of sensitive functions.

#### Remediation

[Describe the best practices that developers should follow to prevent this issue]

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-002"></a>OMTG-RARE-002:  Test for Meaningful Identifiers in Java Bytecode

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

Verify the minifyEnabled is set to true in build.gradle (see below).

#### Black-box Testing

To inspect the Java bytecode for metadata either use the dexdump tool that ships with the Android SDK or a decompiler.

![ProGuard-obfuscated code](/Document/Images/Testcases/OMTG-RARE_Android/proguard.jpg)

#### Remediation

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

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-003"></a>OMTG-RARE-003: Test Jailbreak / Root Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing

Root detection is usually implemented as a number of environmental checks, such as checking for files and processes known to be found only on rooted devices, or artefacts of widely used rooting tools. If you have access to the source code, make sure that there is at least a check for the presence of the "su" binary in common locations, including:

~~~~
/system/bin/su
/system/xbin/su
/sbin/su
~~~~

It is also possible to check for app packages of typical rooting tools, such as Superuser.apk. However, the presence and location of these files varies heavily depending on the specific Android and tool version.

Another option is checking the list of installed apps against a package names of known rooting tools, such as:

~~~~
eu.chainfire.supersu
com.koushikdutta.superuser
~~~~

The package list can be obtained via the PackageManager:

~~~~
final PackageManager pm = getPackageManager();

List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
~~~~

#### Black-box Testing

Install the app on a rooted device and launch the app. If the app functions without any issues, then this test fails.

#### References

- Netspi Blog - https://blog.netspi.com/android-root-detection-techniques/
- InfoSec Institute - http://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion/

### <a name="OMTG-RARE-004"></a>OMTG-RARE-004: Test Verification of Installation Source

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-005"></a>OMTG-RARE-005: Test Simple Debugger Detection / Prevention

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing

Attempt to attach a debugger to the running process. This  should either fail, or the app should terminate or misbehave when the debugger has been detected. For example, if ptrace(PT_DENY_ATTACH) has been called, gdb will crash with a segmentation fault:

(TODO example)

(TODO JDWP)

Note that some anti-debugging implementations respond in a stealthy way so that changes in behaviour are not immediately apparent. For example, a soft token app might not visibly respond when a debugger is detected, but instead secretly alter the state of an internal variable so that an incorrect OTP is generated at a later point. Make sure to run through the complete workflow to determine if attaching the debugger causes a crash or malfunction.

#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-006"></a>OMTG-RARE-006: Test Advanced Jailbreak / Root Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-007"></a>OMTG-RARE-007: Test Advanced Debugging Defenses

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-008"></a>OMTG-RARE-008: Test File Tampering Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-009"></a>OMTG-RARE-009: Test Detection of Reverse Engineering Tools

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-010"></a>OMTG-RARE-010: Test Basic Emulator Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-011"></a>OMTG-RARE-011: Test Memory Tampering Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-012"></a>OMTG-RARE-012: Test Variability of Tampering Responses

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-013"></a>OMTG-RARE-013: Test Binary Encryption

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-014"></a>OMTG-RARE-014: Test Device Binding

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-015"></a>OMTG-RARE-015: Test Advanced Jailbreak / Root Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-016"></a>OMTG-RARE-016: Test Advanced Emulator Detection

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-017"></a>OMTG-RARE-017: Test Integration of SE and/or TEE

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]

### <a name="OMTG-RARE-018"></a>OMTG-RARE-018: Test Advanced Obfuscation

#### Overview

(Give an overview about the functionality and it's potential weaknesses)

#### White-box Testing


#### Black-box Testing


#### References

- [link to relevant how-tos, papers, etc.]
