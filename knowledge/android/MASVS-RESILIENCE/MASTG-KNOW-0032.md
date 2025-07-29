---
masvs_category: MASVS-RESILIENCE
platform: android
title: Runtime Integrity Verification
---

Controls in this category verify the integrity of the app's memory space to defend the app against memory patches applied during runtime. Such patches include unwanted changes to binary code, bytecode, function pointer tables, and important data structures, as well as rogue code loaded into process memory. Integrity can be verified by:

1. comparing the contents of memory or a checksum over the contents to good values,
2. searching memory for the signatures of unwanted modifications.

There's some overlap with the category "detecting reverse engineering tools and frameworks", and, in fact, we demonstrated the signature-based approach in that chapter when we showed how to search process memory for Frida-related strings. Below are a few more examples of various kinds of integrity monitoring.

## Detecting Tampering with the Java Runtime

Hooking frameworks such as @MASTG-TOOL-0027 will inject themselves into the Android Runtime and leave different traces while doing so. These traces can be detected, as shown by this code snippet from the [XPosedDetector](https://github.com/vvb2060/XposedDetector/) project.

```cpp
static jclass findXposedBridge(C_JNIEnv *env, jobject classLoader) {
    return findLoadedClass(env, classLoader, "de/robv/android/xposed/XposedBridge"_iobfs.c_str());
}
void doAntiXposed(C_JNIEnv *env, jobject object, intptr_t hash) {
    if (!add(hash)) {
        debug(env, "checked classLoader %s", object);
        return;
    }
#ifdef DEBUG
    LOGI("doAntiXposed, classLoader: %p, hash: %zx", object, hash);
#endif
    jclass classXposedBridge = findXposedBridge(env, object);
    if (classXposedBridge == nullptr) {
        return;
    }
    if (xposed_status == NO_XPOSED) {
        xposed_status = FOUND_XPOSED;
    }
    disableXposedBridge(env, classXposedBridge);
    if (clearHooks(env, object)) {
#ifdef DEBUG
        LOGI("hooks cleared");
#endif
        if (xposed_status < ANTIED_XPOSED) {
            xposed_status = ANTIED_XPOSED;
        }
    }
}
```

## Detecting Native Hooks

By using ELF binaries, native function hooks can be installed by overwriting function pointers in memory (e.g., Global Offset Table or PLT hooking) or patching parts of the function code itself (inline hooking). Checking the integrity of the respective memory regions is one way to detect this kind of hook.

The Global Offset Table (GOT) is used to resolve library functions. During runtime, the dynamic linker patches this table with the absolute addresses of global symbols. _GOT hooks_ overwrite the stored function addresses and redirect legitimate function calls to adversary-controlled code. This type of hook can be detected by enumerating the process memory map and verifying that each GOT entry points to a legitimately loaded library.

In contrast to GNU `ld`, which resolves symbol addresses only after they are needed for the first time (lazy binding), the Android linker resolves all external functions and writes the respective GOT entries immediately after a library is loaded (immediate binding). You can therefore expect all GOT entries to point to valid memory locations in the code sections of their respective libraries during runtime. GOT hook detection methods usually walk the GOT and verify this.

_Inline hooks_ work by overwriting a few instructions at the beginning or end of the function code. During runtime, this so-called trampoline redirects execution to the injected code. You can detect inline hooks by inspecting the prologues and epilogues of library functions for suspect instructions, such as far jumps to locations outside the library.
