---
masvs_v1_id:
- MSTG-RESILIENCE-3
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: android
title: Testing File Integrity Checks
masvs_v1_levels:
- R
profiles: [R]
---

## Bypassing File Integrity Checks

### Bypassing the application-source integrity checks

1. Patch the anti-debugging functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.
2. Use Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file instead of the modified file.
3. Use the kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.

Refer to Method Hooking for examples of patching, code injection, and kernel modules.

### Bypassing the storage integrity checks

1. Retrieve the data from the device.
2. Alter the retrieved data and then put it back into storage.

## Effectiveness Assessment

**Application-source integrity checks:**

Run the app in an unmodified state and make sure that everything works. Apply simple patches to `classes.dex` and any .so libraries in the app package. Re-package and re-sign the app as described in the "Basic Security Testing" chapter, then run the app. The app should detect the modification and respond in some way. At the very least, the app should alert the user and/or terminate. Work on bypassing the defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti-debugging code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

**Storage integrity checks:**

An approach similar to that for application-source integrity checks applies. Answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by changing the contents of a file or a key-value)?
- How difficult is getting the HMAC key or the asymmetric private key?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?
