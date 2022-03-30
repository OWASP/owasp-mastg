# Android Anti-Reversing Defenses

## Testing Root Detection (MSTG-RESILIENCE-1)

### Overview

In the context of anti-reversing, the goal of root detection is to make running the app on a rooted device a bit more difficult, which in turn blocks some of the tools and techniques reverse engineers like to use. Like most other defenses, root detection is not very effective by itself, but implementing multiple root checks that are scattered throughout the app can improve the effectiveness of the overall anti-tampering scheme.

For Android, we define "root detection" a bit more broadly, including custom ROMs detection, i.e., determining whether the device is a stock Android build or a custom build.

### Common Root Detection Methods

In the following section, we list some common root detection methods you'll encounter. You'll find some of these methods implemented in the [crackme examples](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes "OWASP Mobile Crackmes") that accompany the OWASP Mobile Testing Guide.

Root detection can also be implemented through libraries such as [RootBeer](https://github.com/scottyab/rootbeer "RootBeer").

#### SafetyNet

SafetyNet is an Android API that provides a set of services and creates profiles of devices according to software and hardware information. This profile is then compared to a list of accepted device models that have passed Android compatibility testing. Google [recommends](https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNet "SafetyNet Documentation") using the feature as "an additional in-depth defense signal as part of an anti-abuse system".

How exactly SafetyNet works is not well documented and may change at any time. When you call this API, SafetyNet downloads a binary package containing the device validation code provided from Google, and the code is then dynamically executed via reflection. An [analysis by John Kozyrakis](https://koz.io/inside-safetynet/ "SafetyNet: Google's tamper detection for Android") showed that SafetyNet also attempts to detect whether the device is rooted, but exactly how that's determined is unclear.

To use the API, an app may call the `SafetyNetApi.attest` method (which returns a JWS message with the *Attestation Result*) and then check the following fields:

- `ctsProfileMatch`: If 'true', the device profile matches one of Google's listed devices.
- `basicIntegrity`: If 'true', the device running the app likely hasn't been tampered with.
- `nonces`: To match the response to its request.
- `timestampMs`: To check how much time has passed since you made the request and you got the response. A delayed response may suggest suspicious activity.
- `apkPackageName`, `apkCertificateDigestSha256`, `apkDigestSha256`: Provide information about the APK, which is used to verify the identity of the calling app. These parameters are absent if the API cannot reliably determine the APK information.

The following is a sample attestation result:

```json
{
  "nonce": "R2Rra24fVm5xa2Mg",
  "timestampMs": 9860437986543,
  "apkPackageName": "com.package.name.of.requesting.app",
  "apkCertificateDigestSha256": ["base64 encoded, SHA-256 hash of the
                                  certificate used to sign requesting app"],
  "apkDigestSha256": "base64 encoded, SHA-256 hash of the app's APK",
  "ctsProfileMatch": true,
  "basicIntegrity": true,
}
```

##### ctsProfileMatch Vs basicIntegrity

The SafetyNet Attestation API initially provided a single value called `basicIntegrity` to help developers determine the integrity of a device. As the API evolved, Google introduced a new, stricter check whose results appear in a value called `ctsProfileMatch`, which allows developers to more finely evaluate the devices on which their app is running.

In broad terms, `basicIntegrity` gives you a signal about the general integrity of the device and its API. Many Rooted devices fail `basicIntegrity`, as do emulators, virtual devices, and devices with signs of tampering, such as API hooks.

On the other hand, `ctsProfileMatch` gives you a much stricter signal about the compatibility of the device. Only unmodified devices that have been certified by Google can pass `ctsProfileMatch`. Devices that will fail `ctsProfileMatch` include the following:

- Devices that fail `basicIntegrity`
- Devices with an unlocked bootloader
- Devices with a custom system image (custom ROM)
- Devices for which the manufacturer didn't apply for, or pass, Google certification
- Devices with a system image built directly from the Android Open Source Program source files
- Devices with a system image distributed as part of a beta or developer preview program (including the Android Beta Program)

##### Recommendations when using `SafetyNetApi.attest`

- Create a large (16 bytes or longer) random number on your server using a cryptographically-secure random function so that a malicious user can not reuse a successful attestation result in place of an unsuccessful result
- Trust APK information (`apkPackageName`, `apkCertificateDigestSha256` and `apkDigestSha256`) only if the value of `ctsProfileMatch` is true.
- The entire JWS response should be sent to your server, using a secure connection, for verification. It isn't recommended to perform the verification directly in the app because, in that case, there is no guarantee that the verification logic itself hasn't been modified.
- The `verify` method only validates that the JWS message was signed by SafetyNet. It doesn't verify that the payload of the verdict matches your expectations. As useful as this service may seem, it is designed for test purposes only, and it has very strict usage quotas of 10,000 requests per day, per project which will not be increased upon request. Hence, you should refer [SafetyNet Verification Samples](https://github.com/googlesamples/android-play-safetynet/tree/master/server/java/src/main/java "Google SafetyNet Sample") and implement the digital signature verification logic on your server in a way that it doesn't depend on Google's servers.
- The SafetyNet Attestation API gives you a snapshot of the state of a device at the moment when the attestation request was made. A successful attestation doesn't necessarily mean that the device would have passed attestation in the past, or that it will in the future. It's recommended to plan a strategy to use the least amount of attestations required to satisfy the use case.
- To prevent inadvertently reaching your `SafetyNetApi.attest` quota and getting attestation errors, you should build a system that monitors your usage of the API and warns you well before you reach your quota so you can get it increased. You should also be prepared to handle attestation failures because of an exceeded quota and avoid blocking all your users in this situation. If you are close to reaching your quota, or expect a short-term spike that may lead you to exceed your quota, you can submit this [form](https://support.google.com/googleplay/android-developer/contact/safetynetqr "quota request") to request short or long-term increases to the quota for your API key. This process, as well as the additional quota, is free of charge.

Follow this [checklist](https://developer.android.com/training/safetynet/attestation-checklist "attestation checklist") to ensure that you've completed each of the steps needed to integrate the `SafetyNetApi.attest` API into the app.

#### Programmatic Detection

##### File existence checks

Perhaps the most widely used method of programmatic detection is checking for files typically found on rooted devices, such as package files of common rooting apps and their associated files and directories, including the following:

```default
/system/app/Superuser.apk
/system/etc/init.d/99SuperSUDaemon
/dev/com.koushikdutta.superuser.daemon/
/system/xbin/daemonsu
```

Detection code also often looks for binaries that are usually installed once a device has been rooted. These searches include checking for busybox and attempting to open the *su* binary at different locations:

```default
/sbin/su
/system/bin/su
/system/bin/failsafe/su
/system/xbin/su
/system/xbin/busybox
/system/sd/xbin/su
/data/local/su
/data/local/xbin/su
/data/local/bin/su
```

Checking whether `su` is on the PATH also works:

```java
    public static boolean checkRoot(){
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                return true;
            }
        }
        return false;
    }
```

File checks can be easily implemented in both Java and native code. The following JNI example (adapted from [rootinspector](https://github.com/devadvance/rootinspector/ "rootinspector")) uses the `stat` system call to retrieve information about a file and returns "1" if the file exists.

```c
jboolean Java_com_example_statfile(JNIEnv * env, jobject this, jstring filepath) {
  jboolean fileExists = 0;
  jboolean isCopy;
  const char * path = (*env)->GetStringUTFChars(env, filepath, &isCopy);
  struct stat fileattrib;
  if (stat(path, &fileattrib) < 0) {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat error: [%s]", strerror(errno));
  } else
  {
    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_TAG, "NATIVE: stat success, access perms: [%d]", fileattrib.st_mode);
    return 1;
  }

  return 0;
}
```

##### Executing `su` and other commands

Another way of determining whether `su` exists is attempting to execute it through the `Runtime.getRuntime.exec` method. An IOException will be thrown if `su` is not on the PATH. The same method can be used to check for other programs often found on rooted devices, such as busybox and the symbolic links that typically point to it.

##### Checking running processes

Supersu-by far the most popular rooting tool-runs an authentication daemon named `daemonsu`, so the presence of this process is another sign of a rooted device. Running processes can be enumerated with the `ActivityManager.getRunningAppProcesses` and `manager.getRunningServices` APIs, the `ps` command, and browsing through the `/proc` directory. The following is an example implemented in [rootinspector](https://github.com/devadvance/rootinspector/ "rootinspector"):

```java
    public boolean checkRunningProcesses() {

      boolean returnValue = false;

      // Get currently running application processes
      List<RunningServiceInfo> list = manager.getRunningServices(300);

      if(list != null){
        String tempName;
        for(int i=0;i<list.size();++i){
          tempName = list.get(i).process;

          if(tempName.contains("supersu") || tempName.contains("superuser")){
            returnValue = true;
          }
        }
      }
      return returnValue;
    }
```

##### Checking installed app packages

You can use the Android package manager to obtain a list of installed packages. The following package names belong to popular rooting tools:

```default
com.thirdparty.superuser
eu.chainfire.supersu
com.noshufou.android.su
com.koushikdutta.superuser
com.zachspong.temprootremovejb
com.ramdroid.appquarantine
com.topjohnwu.magisk
```

##### Checking for writable partitions and system directories

Unusual permissions on system directories may indicate a customized or rooted device. Although the system and data directories are normally mounted read-only, you'll sometimes find them mounted read-write when the device is rooted. Look for these filesystems mounted with the "rw" flag or try to create a file in the data directories.

##### Checking for custom Android builds

Checking for signs of test builds and custom ROMs is also helpful. One way to do this is to check the BUILD tag for test-keys, which normally [indicate a custom Android image](https://resources.infosecinstitute.com/android-hacking-security-part-8-root-detection-evasion// "InfoSec Institute - Android Root Detection and Evasion"). [Check the BUILD tag as follows](https://github.com/scottyab/rootbeer/blob/master/rootbeerlib/src/main/java/com/scottyab/rootbeer/RootBeer.java#L76 "Rootbeer - detectTestKeys function"):

```java
private boolean isTestKeyBuild()
{
String str = Build.TAGS;
if ((str != null) && (str.contains("test-keys")));
for (int i = 1; ; i = 0)
  return i;
}
```

Missing Google Over-The-Air (OTA) certificates is another sign of a custom ROM: on stock Android builds, [OTA updates Google's public certificates](https://blog.netspi.com/android-root-detection-techniques/ "Android Root Detection Techniques").

#### Bypassing Root Detection

Run execution traces with jdb, [DDMS](https://developer.android.com/studio/profile/monitor "DDMS"), `strace`, and/or kernel modules to find out what the app is doing. You'll usually see all kinds of suspect interactions with the operating system, such as opening `su` for reading and obtaining a list of processes. These interactions are surefire signs of root detection. Identify and deactivate the root detection mechanisms, one at a time. If you're performing a black box resilience assessment, disabling the root detection mechanisms is your first step.

To bypass these checks, you can use several techniques, most of which were introduced in the "Reverse Engineering and Tampering" chapter:

- Renaming binaries. For example, in some cases simply renaming the `su` binary is enough to defeat root detection (try not to break your environment though!).
- Unmounting `/proc` to prevent reading of process lists. Sometimes, the unavailability of `/proc` is enough to bypass such checks.
- Using Frida or Xposed to hook APIs on the Java and native layers. This hides files and processes, hides the contents of files, and returns all kinds of bogus values that the app requests.
- Hooking low-level APIs by using kernel modules.
- Patching the app to remove the checks.

### Effectiveness Assessment

Check for root detection mechanisms, including the following criteria:

- Multiple detection methods are scattered throughout the app (as opposed to putting everything into a single method).
- The root detection mechanisms operate on multiple API layers (Java APIs, native library functions, assembler/system calls).
- The mechanisms are somehow original (they're not copied and pasted from StackOverflow or other sources).

Develop bypass methods for the root detection mechanisms and answer the following questions:

- Can the mechanisms be easily bypassed with standard tools, such as RootCloak?
- Is static/dynamic analysis necessary to handle the root detection?
- Do you need to write custom code?
- How long did successfully bypassing the mechanisms take?
- What is your assessment of the difficulty of bypassing the mechanisms?

If root detection is missing or too easily bypassed, make suggestions in line with the effectiveness criteria listed above. These suggestions may include more detection mechanisms and better integration of existing mechanisms with other defenses.

## Testing Anti-Debugging Detection (MSTG-RESILIENCE-2)

### Overview

Debugging is a highly effective way to analyze runtime app behavior. It allows the reverse engineer to step through the code, stop app execution at arbitrary points, inspect the state of variables, read and modify memory, and a lot more.

Anti-debugging features can be preventive or reactive. As the name implies, preventive anti-debugging prevents the debugger from attaching in the first place; reactive anti-debugging involves detecting debuggers and reacting to them in some way (e.g., terminating the app or triggering hidden behavior). The "more-is-better" rule applies: to maximize effectiveness, defenders combine multiple methods of prevention and detection that operate on different API layers and are well distributed throughout the app.

As mentioned in the "Reverse Engineering and Tampering" chapter, we have to deal with two debugging protocols on Android: we can debug on the Java level with JDWP or on the native layer via a ptrace-based debugger. A good anti-debugging scheme should defend against both types of debugging.

### JDWP Anti-Debugging

In the chapter "Reverse Engineering and Tampering", we talked about JDWP, the protocol used for communication between the debugger and the Java Virtual Machine. We showed that it is easy to enable debugging for any app by patching its manifest file, and changing the `ro.debuggable` system property which enables debugging for all apps. Let's look at a few things developers do to detect and disable JDWP debuggers.

#### Checking the Debuggable Flag in ApplicationInfo

We have already encountered the `android:debuggable` attribute. This flag in the Android Manifest determines whether the JDWP thread is started for the app. Its value can be determined programmatically, via the app's `ApplicationInfo` object. If the flag is set, the manifest has been tampered with and allows debugging.

```java
    public static boolean isDebuggable(Context context){

        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

    }
```

#### isDebuggerConnected

While this might be pretty obvious to circumvent for a reverse engineer, you can use `isDebuggerConnected` from the `android.os.Debug` class to determine whether a debugger is connected.

```java
    public static boolean detectDebugger() {
        return Debug.isDebuggerConnected();
    }
```

The same API can be called via native code by accessing the DvmGlobals global structure.

```c
JNIEXPORT jboolean JNICALL Java_com_test_debugging_DebuggerConnectedJNI(JNIenv * env, jobject obj) {
    if (gDvm.debuggerConnected || gDvm.debuggerActive)
        return JNI_TRUE;
    return JNI_FALSE;
}
```

#### Timer Checks

`Debug.threadCpuTimeNanos` indicates the amount of time that the current thread has been executing code. Because debugging slows down process execution, [you can use the difference in execution time to guess whether a debugger is attached](https://www.yumpu.com/en/document/read/15228183/android-reverse-engineering-defenses-bluebox-labs "Bluebox Security - Android Reverse Engineering & Defenses").

```java
static boolean detect_threadCpuTimeNanos(){
  long start = Debug.threadCpuTimeNanos();

  for(int i=0; i<1000000; ++i)
    continue;

  long stop = Debug.threadCpuTimeNanos();

  if(stop - start < 10000000) {
    return false;
  }
  else {
    return true;
  }
}
```

#### Messing with JDWP-Related Data Structures

In Dalvik, the global virtual machine state is accessible via the `DvmGlobals` structure. The global variable gDvm holds a pointer to this structure. `DvmGlobals` contains various variables and pointers that are important for JDWP debugging and can be tampered with.

```c
struct DvmGlobals {
    /*
     * Some options that could be worth tampering with :)
     */

    bool        jdwpAllowed;        // debugging allowed for this process?
    bool        jdwpConfigured;     // has debugging info been provided?
    JdwpTransportType jdwpTransport;
    bool        jdwpServer;
    char*       jdwpHost;
    int         jdwpPort;
    bool        jdwpSuspend;

    Thread*     threadList;

    bool        nativeDebuggerActive;
    bool        debuggerConnected;      /* debugger or DDMS is connected */
    bool        debuggerActive;         /* debugger is making requests */
    JdwpState*  jdwpState;

};
```

For example, [setting the gDvm.methDalvikDdmcServer_dispatch function pointer to NULL crashes the JDWP thread](https://github.com/crazykid95/Backup-Mobile-Security-Report/blob/master/AndroidREnDefenses201305.pdf "Bluebox Security - Android Reverse Engineering & Defenses"):

```c
JNIEXPORT jboolean JNICALL Java_poc_c_crashOnInit ( JNIEnv* env , jobject ) {
  gDvm.methDalvikDdmcServer_dispatch = NULL;
}
```

You can disable debugging by using similar techniques in ART even though the gDvm variable is not available. The ART runtime exports some of the vtables of JDWP-related classes as global symbols (in C++, vtables are tables that hold pointers to class methods). This includes the vtables of the classes `JdwpSocketState` and `JdwpAdbState`, which handle JDWP connections via network sockets and ADB, respectively. You can manipulate the behavior of the debugging runtime [by overwriting the method pointers in the associated vtables](https://web.archive.org/web/20200307152820/https://www.vantagepoint.sg/blog/88-anti-debugging-fun-with-android-art "Anti-Debugging Fun with Android ART") (archived).

One way to overwrite the method pointers is to overwrite the address of the function `jdwpAdbState::ProcessIncoming` with the address of `JdwpAdbState::Shutdown`. This will cause the debugger to disconnect immediately.

```c
#include <jni.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <jdwp/jdwp.h>

#define log(FMT, ...) __android_log_print(ANDROID_LOG_VERBOSE, "JDWPFun", FMT, ##__VA_ARGS__)

// Vtable structure. Just to make messing around with it more intuitive

struct VT_JdwpAdbState {
    unsigned long x;
    unsigned long y;
    void * JdwpSocketState_destructor;
    void * _JdwpSocketState_destructor;
    void * Accept;
    void * showmanyc;
    void * ShutDown;
    void * ProcessIncoming;
};

extern "C"

JNIEXPORT void JNICALL Java_sg_vantagepoint_jdwptest_MainActivity_JDWPfun(
        JNIEnv *env,
        jobject /* this */) {

    void* lib = dlopen("libart.so", RTLD_NOW);

    if (lib == NULL) {
        log("Error loading libart.so");
        dlerror();
    }else{

        struct VT_JdwpAdbState *vtable = ( struct VT_JdwpAdbState *)dlsym(lib, "_ZTVN3art4JDWP12JdwpAdbStateE");

        if (vtable == 0) {
            log("Couldn't resolve symbol '_ZTVN3art4JDWP12JdwpAdbStateE'.\n");
        }else {

            log("Vtable for JdwpAdbState at: %08x\n", vtable);

            // Let the fun begin!

            unsigned long pagesize = sysconf(_SC_PAGE_SIZE);
            unsigned long page = (unsigned long)vtable & ~(pagesize-1);

            mprotect((void *)page, pagesize, PROT_READ | PROT_WRITE);

            vtable->ProcessIncoming = vtable->ShutDown;

            // Reset permissions & flush cache

            mprotect((void *)page, pagesize, PROT_READ);

        }
    }
}
```

### Traditional Anti-Debugging

On Linux, the [`ptrace` system call](http://man7.org/linux/man-pages/man2/ptrace.2.html "Ptrace man page") is used to observe and control the execution of a process (the _tracee_) and to examine and change that process' memory and registers. `ptrace` is the primary way to implement system call tracing and breakpoint debugging in native code. Most JDWP anti-debugging tricks (which may be safe for timer-based checks) won't catch classical debuggers based on `ptrace` and therefore, many Android anti-debugging tricks include `ptrace`, often exploiting the fact that only one debugger at a time can attach to a process.

#### Checking TracerPid

When you debug an app and set a breakpoint on native code, Android Studio will copy the needed files to the target device and start the lldb-server which will use `ptrace` to attach to the process. From this moment on, if you inspect the [status file](http://man7.org/linux/man-pages/man5/proc.5.html "/proc/[pid]/status") of the debugged process (`/proc/<pid>/status` or `/proc/self/status`), you will see that the "TracerPid" field has a value different from 0, which is a sign of debugging.

> Remember that **this only applies to native code**. If you're debugging a Java/Kotlin-only app the value of the "TracerPid" field should be 0.

This technique is usually applied within the JNI native libraries in C, as shown in [Google's gperftools (Google Performance Tools)) Heap Checker](https://github.com/gperftools/gperftools/blob/master/src/heap-checker.cc#L112 "heap-checker.cc - IsDebuggerAttached") implementation of the `IsDebuggerAttached` method. However, if you prefer to include this check as part of your Java/Kotlin code you can refer to this Java implementation of the `hasTracerPid` method from [Tim Strazzere's Anti-Emulator project](https://github.com/strazzere/anti-emulator/ "anti-emulator").

When trying to implement such a method yourself, you can manually check the value of TracerPid with ADB. The following listing uses Google's NDK sample app [hello-jni (com.example.hellojni)](https://github.com/android/ndk-samples/tree/android-mk/hello-jni "hello-jni sample") to perform the check after attaching Android Studio's debugger:

```bash
$ adb shell ps -A | grep com.example.hellojni
u0_a271      11657   573 4302108  50600 ptrace_stop         0 t com.example.hellojni
$ adb shell cat /proc/11657/status | grep -e "^TracerPid:" | sed "s/^TracerPid:\t//"
TracerPid:      11839
$ adb shell ps -A | grep 11839
u0_a271      11839 11837   14024   4548 poll_schedule_timeout 0 S lldb-server
```

You can see how the status file of com.example.hellojni (PID=11657) contains a TracerPID of 11839, which we can identify as the lldb-server process.

#### Using Fork and ptrace

You can prevent debugging of a process by forking a child process and attaching it to the parent as a debugger via code similar to the following simple example code:

```c
void fork_and_attach()
{
  int pid = fork();

  if (pid == 0)
    {
      int ppid = getppid();

      if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
          waitpid(ppid, NULL, 0);

          /* Continue the parent process */
          ptrace(PTRACE_CONT, NULL, NULL);
        }
    }
}
```

With the child attached, further attempts to attach to the parent will fail. We can verify this by compiling the code into a JNI function and packing it into an app we run on the device.

```bash
root@android:/ # ps | grep -i anti
u0_a151   18190 201   1535844 54908 ffffffff b6e0f124 S sg.vantagepoint.antidebug
u0_a151   18224 18190 1495180 35824 c019a3ac b6e0ee5c S sg.vantagepoint.antidebug
```

Attempting to attach to the parent process with gdbserver fails with an error:

```bash
root@android:/ # ./gdbserver --attach localhost:12345 18190
warning: process 18190 is already traced by process 18224
Cannot attach to lwp 18190: Operation not permitted (1)
Exiting
```

You can easily bypass this failure, however, by killing the child and "freeing" the parent from being traced. You'll therefore usually find more elaborate schemes, involving multiple processes and threads as well as some form of monitoring to impede tampering. Common methods include

- forking multiple processes that trace one another,
- keeping track of running processes to make sure the children stay alive,
- monitoring values in the `/proc` filesystem, such as TracerPID in `/proc/pid/status`.

Let's look at a simple improvement for the method above. After the initial `fork`, we launch in the parent an extra thread that continually monitors the child's status. Depending on whether the app has been built in debug or release mode (which is indicated by the `android:debuggable` flag in the manifest), the child process should do one of the following things:

- In release mode: The call to ptrace fails and the child crashes immediately with a segmentation fault (exit code 11).
- In debug mode: The call to ptrace works and the child should run indefinitely. Consequently, a call to `waitpid(child_pid)` should never return. If it does, something is fishy and we would kill the whole process group.

The following is the complete code for implementing this improvement with a JNI function:

```c
#include <jni.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <pthread.h>

static int child_pid;

void *monitor_pid() {

    int status;

    waitpid(child_pid, &status, 0);

    /* Child status should never change. */

    _exit(0); // Commit seppuku

}

void anti_debug() {

    child_pid = fork();

    if (child_pid == 0)
    {
        int ppid = getppid();
        int status;

        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
        {
            waitpid(ppid, &status, 0);

            ptrace(PTRACE_CONT, ppid, NULL, NULL);

            while (waitpid(ppid, &status, 0)) {

                if (WIFSTOPPED(status)) {
                    ptrace(PTRACE_CONT, ppid, NULL, NULL);
                } else {
                    // Process has exited
                    _exit(0);
                }
            }
        }

    } else {
        pthread_t t;

        /* Start the monitoring thread */
        pthread_create(&t, NULL, monitor_pid, (void *)NULL);
    }
}

JNIEXPORT void JNICALL
Java_sg_vantagepoint_antidebug_MainActivity_antidebug(JNIEnv *env, jobject instance) {

    anti_debug();
}
```

Again, we pack this into an Android app to see if it works. Just as before, two processes show up when we run the app's debug build.

```bash
root@android:/ # ps | grep -I anti-debug
u0_a152   20267 201   1552508 56796 ffffffff b6e0f124 S sg.vantagepoint.anti-debug
u0_a152   20301 20267 1495192 33980 c019a3ac b6e0ee5c S sg.vantagepoint.anti-debug
```

However, if we terminate the child process at this point, the parent exits as well:

```bash
root@android:/ # kill -9 20301
130|root@hammerhead:/ # cd /data/local/tmp
root@android:/ # ./gdbserver --attach localhost:12345 20267
gdbserver: unable to open /proc file '/proc/20267/status'
Cannot attach to lwp 20267: No such file or directory (2)
Exiting
```

To bypass this, we must modify the app's behavior slightly (the easiest ways to do so are patching the call to `_exit` with NOPs and hooking the function `_exit` in `libc.so`). At this point, we have entered the proverbial "arms race": implementing more intricate forms of this defense as well as bypassing it are always possible.

### Bypassing Debugger Detection

There's no generic way to bypass anti-debugging: the best method depends on the particular mechanism(s) used to prevent or detect debugging and the other defenses in the overall protection scheme. For example, if there are no integrity checks or you've already deactivated them, patching the app might be the easiest method. In other cases, a hooking framework or kernel modules might be preferable.
The following methods describe different approaches to bypass debugger detection:

- Patching the anti-debugging functionality: Disable the unwanted behavior by simply overwriting it with NOP instructions. Note that more complex patches may be required if the anti-debugging mechanism is well designed.
- Using Frida or Xposed to hook APIs on the Java and native layers: manipulate the return values of functions such as `isDebuggable` and `isDebuggerConnected` to hide the debugger.
- Changing the environment: Android is an open environment. If nothing else works, you can modify the operating system to subvert the assumptions the developers made when designing the anti-debugging tricks.

#### Bypassing Example: UnCrackable App for Android Level 2

When dealing with obfuscated apps, you'll often find that developers purposely "hide away" data and functionality in native libraries. You'll find an example of this in level 2 of the "UnCrackable App for Android".

At first glance, the code looks like the prior challenge. A class called `CodeCheck` is responsible for verifying the code entered by the user. The actual check appears to occur in the `bar` method, which is declared as a *native* method.

```java
package sg.vantagepoint.uncrackable2;

public class CodeCheck {
    public CodeCheck() {
        super();
    }

    public boolean a(String arg2) {
        return this.bar(arg2.getBytes());
    }

    private native boolean bar(byte[] arg1) {
    }
}

    static {
        System.loadLibrary("foo");
    }
```

Please see [different proposed solutions for the Android Crackme Level 2](https://github.com/OWASP/owasp-mstg/tree/master/Crackmes#uncrackable-app-for-android-level-2 "Solutions Android Crackme Level 2") in GitHub.

### Effectiveness Assessment

Check for anti-debugging mechanisms, including the following criteria:

- Attaching jdb and ptrace-based debuggers fails or causes the app to terminate or malfunction.
- Multiple detection methods are scattered throughout the app's source code (as opposed to their all being in a single method or function).
- The anti-debugging defenses operate on multiple API layers (Java, native library functions, assembler/system calls).
- The mechanisms are somehow original (as opposed to being copied and pasted from StackOverflow or other sources).

Work on bypassing the anti-debugging defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti-debugging code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your subjective assessment of the difficulty of bypassing the mechanisms?

If anti-debugging mechanisms are missing or too easily bypassed, make suggestions in line with the effectiveness criteria above. These suggestions may include adding more detection mechanisms and better integration of existing mechanisms with other defenses.

## Testing File Integrity Checks (MSTG-RESILIENCE-3)

### Overview

There are two topics related to file integrity:

 1. _Code integrity checks:_ In the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter, we discussed Android's APK code signature check. We also saw that determined reverse engineers can easily bypass this check by re-packaging and re-signing an app. To make this bypassing process more involved, a protection scheme can be augmented with CRC checks on the app bytecode, native libraries, and important data files. These checks can be implemented on both the Java and the native layer. The idea is to have additional controls in place so that the app only runs correctly in its unmodified state, even if the code signature is valid.
 2. _The file storage integrity checks:_ The integrity of files that the application stores on the SD card or public storage and the integrity of key-value pairs that are stored in `SharedPreferences` should be protected.

#### Sample Implementation - Application Source Code

Integrity checks often calculate a checksum or hash over selected files. Commonly protected files include

- AndroidManifest.xml,
- class files *.dex,
- native libraries (*.so).

The following [sample implementation from the Android Cracking blog](https://androidcracking.blogspot.com/2011/06/anti-tampering-with-crc-check.html "anti-tampering with crc check") calculates a CRC over `classes.dex` and compares it to the expected value.

```java
private void crcTest() throws IOException {
 boolean modified = false;
 // required dex crc value stored as a text string.
 // it could be any invisible layout element
 long dexCrc = Long.parseLong(Main.MyContext.getString(R.string.dex_crc));

 ZipFile zf = new ZipFile(Main.MyContext.getPackageCodePath());
 ZipEntry ze = zf.getEntry("classes.dex");

 if ( ze.getCrc() != dexCrc ) {
  // dex has been modified
  modified = true;
 }
 else {
  // dex not tampered with
  modified = false;
 }
}
```

#### Sample Implementation - Storage

When providing integrity on the storage itself, you can either create an HMAC over a given key-value pair (as for the Android `SharedPreferences`) or create an HMAC over a complete file that's provided by the file system.

When using an HMAC, you can [use a bouncy castle implementation or the AndroidKeyStore to HMAC the given content](https://web.archive.org/web/20210804035343/https://cseweb.ucsd.edu/~mihir/papers/oem.html "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm").

Complete the following procedure when generating an HMAC with BouncyCastle:

1. Make sure BouncyCastle or SpongyCastle is registered as a security provider.
2. Initialize the HMAC with a key (which can be stored in a keystore).
3. Get the byte array of the content that needs an HMAC.
4. Call `doFinal` on the HMAC with the bytecode.
5. Append the HMAC to the bytearray obtained in step 3.
6. Store the result of step 5.

Complete the following procedure when verifying the HMAC with BouncyCastle:

1. Make sure that BouncyCastle or SpongyCastle is registered as a security provider.
2. Extract the message and the HMAC-bytes as separate arrays.
3. Repeat steps 1-4 of the procedure for generating an HMAC.
4. Compare the extracted HMAC-bytes to the result of step 3.

When generating the HMAC based on the [Android Keystore](https://developer.android.com/training/articles/keystore.html "Android Keystore"), then it is best to only do this for Android 6.0 (API level 23) and higher.

The following is a convenient HMAC implementation without `AndroidKeyStore`:

```java
public enum HMACWrapper {
    HMAC_512("HMac-SHA512"), //please note that this is the spec for the BC provider
    HMAC_256("HMac-SHA256");

    private final String algorithm;

    private HMACWrapper(final String algorithm) {
        this.algorithm = algorithm;
    }

    public Mac createHMAC(final SecretKey key) {
        try {
            Mac e = Mac.getInstance(this.algorithm, "BC");
            SecretKeySpec secret = new SecretKeySpec(key.getKey().getEncoded(), this.algorithm);
            e.init(secret);
            return e;
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException e) {
            //handle them
        }
    }

    public byte[] hmac(byte[] message, SecretKey key) {
        Mac mac = this.createHMAC(key);
        return mac.doFinal(message);
    }

    public boolean verify(byte[] messageWithHMAC, SecretKey key) {
        Mac mac = this.createHMAC(key);
        byte[] checksum = extractChecksum(messageWithHMAC, mac.getMacLength());
        byte[] message = extractMessage(messageWithHMAC, mac.getMacLength());
        byte[] calculatedChecksum = this.hmac(message, key);
        int diff = checksum.length ^ calculatedChecksum.length;

        for (int i = 0; i < checksum.length && i < calculatedChecksum.length; ++i) {
            diff |= checksum[i] ^ calculatedChecksum[i];
        }

        return diff == 0;
    }

    public byte[] extractMessage(byte[] messageWithHMAC) {
        Mac hmac = this.createHMAC(SecretKey.newKey());
        return extractMessage(messageWithHMAC, hmac.getMacLength());
    }

    private static byte[] extractMessage(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] message = new byte[body.length - checksumLength];
            System.arraycopy(body, 0, message, 0, message.length);
            return message;
        } else {
            return new byte[0];
        }
    }

    private static byte[] extractChecksum(byte[] body, int checksumLength) {
        if (body.length >= checksumLength) {
            byte[] checksum = new byte[checksumLength];
            System.arraycopy(body, body.length - checksumLength, checksum, 0, checksumLength);
            return checksum;
        } else {
            return new byte[0];
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}

```

Another way to provide integrity is to sign the byte array you obtained and add the signature to the original byte array.

#### Bypassing File Integrity Checks

##### Bypassing the application-source integrity checks

1. Patch the anti-debugging functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.
2. Use Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file instead of the modified file.
3. Use the kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

##### Bypassing the storage integrity checks

1. Retrieve the data from the device, as described in the "[Testing Device Binding](#testing-device-binding-mstg-resilience-10 "Testing Device Binding")" section.
2. Alter the retrieved data and then put it back into storage.

### Effectiveness Assessment

#### For application-source integrity checks

Run the app in an unmodified state and make sure that everything works. Apply simple patches to `classes.dex` and any .so libraries in the app package. Re-package and re-sign the app as described in the "Basic Security Testing" chapter, then run the app. The app should detect the modification and respond in some way. At the very least, the app should alert the user and/or terminate. Work on bypassing the defenses and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti-debugging code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

#### For storage integrity checks

An approach similar to that for application-source integrity checks applies. Answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by changing the contents of a file or a key-value)?
- How difficult is getting the HMAC key or the asymmetric private key?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

## Testing Reverse Engineering Tools Detection (MSTG-RESILIENCE-4)

### Overview

The presence of tools, frameworks and apps commonly used by reverse engineers may indicate an attempt to reverse engineer the app. Some of these tools can only run on a rooted device, while others force the app into debugging mode or depend on starting a background service on the mobile phone. Therefore, there are different ways that an app may implement to detect a reverse engineering attack and react to it, e.g. by terminating itself.

### Detection Methods

You can detect popular reverse engineering tools that have been installed in an unmodified form by looking for associated application packages, files, processes, or other tool-specific modifications and artifacts. In the following examples, we'll discuss different ways to detect the Frida instrumentation framework, which is used extensively in this guide. Other tools, such as Substrate and Xposed, can be detected similarly. Note that DBI/injection/hooking tools can often be detected implicitly, through runtime integrity checks, which are discussed below.

For instance, in its default configuration on a rooted device, Frida runs on the device as frida-server. When you explicitly attach to a target app (e.g. via frida-trace or the Frida REPL), Frida injects a frida-agent into the memory of the app. Therefore, you may expect to find it there after attaching to the app (and not before). If you check `/proc/<pid>/maps` you'll find the frida-agent as frida-agent-64.so:

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida
71b6bd6000-71b7d62000 r-xp  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7d7f000-71b7e06000 r--p  /data/local/tmp/re.frida.server/frida-agent-64.so
71b7e06000-71b7e28000 rw-p  /data/local/tmp/re.frida.server/frida-agent-64.so
```

The other method (which also works for non-rooted devices) consists of embedding a [frida-gadget](https://www.frida.re/docs/gadget/ "Frida Gadget") into the APK and _forcing_ the app to load it as one of its native libraries. If you inspect the app memory maps after starting the app (no need to attach explicitly to it) you'll find the embedded frida-gadget as libfrida-gadget.so.

```bash
bullhead:/ # cat /proc/18370/maps | grep -i frida

71b865a000-71b97f1000 r-xp  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b9802000-71b988a000 r--p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
71b988a000-71b98ac000 rw-p  /data/app/sg.vp.owasp_mobile.omtg_android-.../lib/arm64/libfrida-gadget.so
```

Looking at these two _traces_ that Frida _lefts behind_, you might already imagine that detecting those would be a trivial task. And actually, so trivial will be bypassing that detection. But things can get much more complicated. The following table shortly presents a set of some typical Frida detection methods and a short discussion on their effectiveness.

> Some of the following detection methods are presented in the article ["The Jiu-Jitsu of Detecting Frida" by Berdhard Mueller](https://web.archive.org/web/20181227120751/http://www.vantagepoint.sg/blog/90-the-jiu-jitsu-of-detecting-frida "The Jiu-Jitsu of Detecting Frida") (archived). Please refer to it for more details and for example code snippets.

| Method | Description | Discussion |
| --- | --- | --- |
| **Checking the App Signature** | In order to embed the frida-gadget within the APK, it would need to be repackaged and resigned. You could check the signature of the APK when the app is starting (e.g. [GET_SIGNING_CERTIFICATES](https://developer.android.com/reference/android/content/pm/PackageManager#GET_SIGNING_CERTIFICATES "GET_SIGNING_CERTIFICATES") since API level 28) and compare it to the one you pinned in your APK. | This is unfortunately too trivial to bypass, e.g. by patching the APK or performing system call hooking. |
| **Check The Environment For Related Artifacts**  |  Artifacts can be package files, binaries, libraries, processes, and temporary files. For Frida, this could be the frida-server running in the target (rooted) system (the daemon responsible for exposing Frida over TCP). Inspect the running services ([`getRunningServices`](https://developer.android.com/reference/android/app/ActivityManager.html#getRunningServices%28int%29 "getRunningServices")) and processes (`ps`) searching for one whose name is "frida-server". You could also walk through the list of loaded libraries and check for suspicious ones (e.g. those including "frida" in their names). | Since Android 7.0 (API level 24), inspecting the running services/processes won't show you daemons like the frida-server as it is not being started by the app itself. Even if it would be possible, bypassing this would be as easy just renaming the corresponding Frida artifact (frida-server/frida-gadget/frida-agent). |
| **Checking For Open TCP Ports** | The frida-server process binds to TCP port 27042 by default. Check whether this port is open is another method of detecting the daemon. | This method detects frida-server in its default mode, but the listening port can be changed via a command line argument, so bypassing this is a little too trivial. |
| **Checking For Ports Responding To D-Bus Auth** | `frida-server` uses the D-Bus protocol to communicate, so you can expect it to respond to D-Bus AUTH. Send a D-Bus AUTH message to every open port and check for an answer, hoping that `frida-server` will reveal itself. | This is a fairly robust method of detecting `frida-server`, but Frida offers alternative modes of operation that don't require frida-server. |
| **Scanning Process Memory for Known Artifacts** | Scan the memory for artifacts found in Frida's libraries, e.g. the string "LIBFRIDA" present in all versions of frida-gadget and frida-agent. For example, use `Runtime.getRuntime().exec` and iterate through the memory mappings listed in `/proc/self/maps` or `/proc/<pid>/maps` (depending on the Android version) searching for the string. | This method is a bit more effective, and it is difficult to bypass with Frida only, especially if some obfuscation has been added and if multiple artifacts are being scanned. However, the chosen artifacts might be patched in the Frida binaries. Find the source code on [Berdhard Mueller's GitHub](https://github.com/b-mueller/frida-detection-demo/blob/master/AntiFrida/app/src/main/cpp/native-lib.cpp "frida-detection-demo"). |

Please remember that this table is far from exhaustive. We could start talking about [named pipes](https://en.wikipedia.org/wiki/Named_pipe "Named Pipes") (used by frida-server for external communication), detecting [trampolines](https://en.wikipedia.org/wiki/Trampoline_%28computing%29 "Trampolines") (indirect jump vectors inserted at the prologue of functions), which would _help_ detecting Substrate or Frida's Interceptor but, for example, won't be effective against Frida's Stalker; and many other, more or less, effective detection methods. Each of them will depend on whether you're using a rooted device, the specific version of the rooting method and/or the version of the tool itself. Further, the app can try to make it harder to detect the implemented protection mechanisms by using various obfuscation techniques, as discussed below in section "[Testing Resiliency Against Reverse Engineering](#testing-obfuscation-mstg-resilience-9 "Testing Resiliency Against Reverse Engineering")". At the end, this is part of the cat and mouse game of protecting data being processed on an untrusted environment (an app running in the user device).

> It is important to note that these controls are only increasing the complexity of the reverse engineering process. If used, the best approach is to combine the controls cleverly instead of using them individually. However, none of them can assure a 100% effectiveness, as the reverse engineer will always have full access to the device and will therefore always win! You also have to consider that integrating some of the controls into your app might increase the complexity of your app and even have an impact on its performance.

### Effectiveness Assessment

Launch the app with various reverse engineering tools and frameworks installed in your test device. Include at least the following: Frida, Xposed, Substrate for Android, RootCloak, Android SSL Trust Killer.

The app should respond in some way to the presence of those tools. For example by:

- Alerting the user and asking for accepting liability.
- Preventing execution by gracefully terminating.
- Securely wiping any sensitive data stored on the device.
- Reporting to a backend server, e.g, for fraud detection.

Next, work on bypassing the detection of the reverse engineering tools and answer the following questions:

- Can the mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- How difficult is identifying the anti reverse engineering code via static and dynamic analysis?
- Did you need to write custom code to disable the defenses? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

The following steps should guide you when bypassing detection of reverse engineering tools:

1. Patch the anti reverse engineering functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.
2. Use Frida or Xposed to hook file system APIs on the Java and native layers. Return a handle to the original file, not the modified file.
3. Use a kernel module to intercept file-related system calls. When the process attempts to open the modified file, return a file descriptor for the unmodified version of the file.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

## Testing Emulator Detection (MSTG-RESILIENCE-5)

### Overview

In the context of anti-reversing, the goal of emulator detection is to increase the difficulty of running the app on an emulated device, which impedes some tools and techniques reverse engineers like to use. This increased difficulty forces the reverse engineer to defeat the emulator checks or utilize the physical device, thereby barring the access required for large-scale device analysis.

### Emulator Detection Examples

There are several indicators that the device in question is being emulated. Although all these API calls can be hooked, these indicators provide a modest first line of defense.

The first set of indicators are in the file `build.prop`.

```default
API Method          Value           Meaning
Build.ABI           armeabi         possibly emulator
BUILD.ABI2          unknown         possibly emulator
Build.BOARD         unknown         emulator
Build.Brand         generic         emulator
Build.DEVICE        generic         emulator
Build.FINGERPRINT   generic         emulator
Build.Hardware      goldfish        emulator
Build.Host          android-test    possibly emulator
Build.ID            FRF91           emulator
Build.MANUFACTURER  unknown         emulator
Build.MODEL         sdk             emulator
Build.PRODUCT       sdk             emulator
Build.RADIO         unknown         possibly emulator
Build.SERIAL        null            emulator
Build.USER          android-build   emulator
```

You can edit the file `build.prop` on a rooted Android device or modify it while compiling AOSP from source. Both techniques will allow you to bypass the static string checks above.

The next set of static indicators utilize the Telephony manager. All Android emulators have fixed values that this API can query.

```default
API                                                     Value                   Meaning
TelephonyManager.getDeviceId()                          0's                     emulator
TelephonyManager.getLine1 Number()                      155552155               emulator
TelephonyManager.getNetworkCountryIso()                 us                      possibly emulator
TelephonyManager.getNetworkType()                       3                       possibly emulator
TelephonyManager.getNetworkOperator().substring(0,3)    310                     possibly emulator
TelephonyManager.getNetworkOperator().substring(3)      260                     possibly emulator
TelephonyManager.getPhoneType()                         1                       possibly emulator
TelephonyManager.getSimCountryIso()                     us                      possibly emulator
TelephonyManager.getSimSerial Number()                  89014103211118510720    emulator
TelephonyManager.getSubscriberId()                      310260000000000         emulator
TelephonyManager.getVoiceMailNumber()                   15552175049             emulator
```

Keep in mind that a hooking framework, such as Xposed or Frida, can hook this API to provide false data.

### Bypassing Emulator Detection

1. Patch the emulator detection functionality. Disable the unwanted behavior by simply overwriting the associated bytecode or native code with NOP instructions.
2. Use Frida or Xposed APIs to hook file system APIs on the Java and native layers. Return innocent-looking values (preferably taken from a real device) instead of the telltale emulator values. For example, you can override the `TelephonyManager.getDeviceID` method to return an IMEI value.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

### Effectiveness Assessment

Install and run the app in the emulator. The app should detect that it is being executed in an emulator and terminate or refuse to execute the functionality that's meant to be protected.

Work on bypassing the defenses and answer the following questions:

- How difficult is identifying the emulator detection code via static and dynamic analysis?
- Can the detection mechanisms be bypassed trivially (e.g., by hooking a single API function)?
- Did you need to write custom code to disable the anti-emulation feature(s)? How much time did you need?
- What is your assessment of the difficulty of bypassing the mechanisms?

## Testing Runtime Integrity Checks (MSTG-RESILIENCE-6)

### Overview

Controls in this category verify the integrity of the app's memory space to defend the app against memory patches applied during runtime. Such patches include unwanted changes to binary code, bytecode, function pointer tables, and important data structures, as well as rogue code loaded into process memory. Integrity can be verified by:

1. comparing the contents of memory or a checksum over the contents to good values,
2. searching memory for the signatures of unwanted modifications.

There's some overlap with the category "detecting reverse engineering tools and frameworks", and, in fact, we demonstrated the signature-based approach in that chapter when we showed how to search process memory for Frida-related strings. Below are a few more examples of various kinds of integrity monitoring.

#### Runtime Integrity Check Examples

##### Detecting tampering with the Java Runtime**

This detection code is from the [dead && end blog](https://d3adend.org/blog/?p=589 "dead && end blog - Android Anti-Hooking Techniques in Java").

```java
try {
  throw new Exception();
}
catch(Exception e) {
  int zygoteInitCallCount = 0;
  for(StackTraceElement stackTraceElement : e.getStackTrace()) {
    if(stackTraceElement.getClassName().equals("com.android.internal.os.ZygoteInit")) {
      zygoteInitCallCount++;
      if(zygoteInitCallCount == 2) {
        Log.wtf("HookDetection", "Substrate is active on the device.");
      }
    }
    if(stackTraceElement.getClassName().equals("com.saurik.substrate.MS$2") &&
        stackTraceElement.getMethodName().equals("invoked")) {
      Log.wtf("HookDetection", "A method on the stack trace has been hooked using Substrate.");
    }
    if(stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
        stackTraceElement.getMethodName().equals("main")) {
      Log.wtf("HookDetection", "Xposed is active on the device.");
    }
    if(stackTraceElement.getClassName().equals("de.robv.android.xposed.XposedBridge") &&
        stackTraceElement.getMethodName().equals("handleHookedMethod")) {
      Log.wtf("HookDetection", "A method on the stack trace has been hooked using Xposed.");
    }

  }
}
```

##### Detecting Native Hooks

By using ELF binaries, native function hooks can be installed by overwriting function pointers in memory (e.g., Global Offset Table or PLT hooking) or patching parts of the function code itself (inline hooking). Checking the integrity of the respective memory regions is one way to detect this kind of hook.

The Global Offset Table (GOT) is used to resolve library functions. During runtime, the dynamic linker patches this table with the absolute addresses of global symbols. *GOT hooks* overwrite the stored function addresses and redirect legitimate function calls to adversary-controlled code. This type of hook can be detected by enumerating the process memory map and verifying that each GOT entry points to a legitimately loaded library.

In contrast to GNU `ld`, which resolves symbol addresses only after they are needed for the first time (lazy binding), the Android linker resolves all external functions and writes the respective GOT entries immediately after a library is loaded (immediate binding). You can therefore expect all GOT entries to point to valid memory locations in the code sections of their respective libraries during runtime. GOT hook detection methods usually walk the GOT and verify this.

*Inline hooks* work by overwriting a few instructions at the beginning or end of the function code. During runtime, this so-called trampoline redirects execution to the injected code. You can detect inline hooks by inspecting the prologues and epilogues of library functions for suspect instructions, such as far jumps to locations outside the library.

### Bypass and Effectiveness Assessment

Make sure that all file-based detection of reverse engineering tools is disabled. Then, inject code by using Xposed, Frida, and Substrate, and attempt to install native hooks and Java method hooks. The app should detect the "hostile" code in its memory and respond accordingly.

Work on bypassing the checks with the following techniques:

1. Patch the integrity checks. Disable the unwanted behavior by overwriting the respective bytecode or native code with NOP instructions.
2. Use Frida or Xposed to hook the APIs used for detection and return fake values.

Refer to the "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" chapter for examples of patching, code injection, and kernel modules.

## Testing Obfuscation (MSTG-RESILIENCE-9)

### Overview

The chapter ["Mobile App Tampering and Reverse Engineering"](0x04c-Tampering-and-Reverse-Engineering.md#obfuscation) introduces several well-known obfuscation techniques that can be used in mobile apps in general.

Android apps can implement some of those obfuscation techniques using different tooling. For example, [ProGuard](0x08-Testing-Tools.md#proguard) offers an easy way to shrink and obfuscate code and to strip unneeded debugging information from the bytecode of Android Java apps. It replaces identifiers, such as class names, method names, and variable names, with meaningless character strings. This is a type of layout obfuscation, which doesn't impact the program's performance.

> Decompiling Java classes is trivial, therefore it is recommended to always applying some basic obfuscation to the production bytecode.

Learn more about Android obfuscation techniques:

- ["Security Hardening of Android Native Code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) by Gautam Arvind
- ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) by Eduardo Novella
- ["Challenges of Native Android Applications: Obfuscation and Vulnerabilities"](https://www.theses.fr/2020REN1S047.pdf) by Pierre Graux

#### Using ProGuard

Developers use the build.gradle file to enable obfuscation. In the example below, you can see that `minifyEnabled` and `proguardFiles` are set. Creating exceptions to protect some classes from obfuscation (with `-keepclassmembers` and `-keep class`) is common. Therefore, auditing the ProGuard configuration file to see what classes are exempted is important. The `getDefaultProguardFile('proguard-android.txt')` method gets the default ProGuard settings from the `<Android SDK>/tools/proguard/` folder.

Further information on how to shrink, obfuscate, and optimize your app can be found in the [Android developer documentation](https://developer.android.com/studio/build/shrink-code "Shrink, obfuscate, and optimize your app").

> When you build you project using Android Studio 3.4 or Android Gradle plugin 3.4.0 or higher, the plugin no longer uses ProGuard to perform compile-time code optimization. Instead, the plugin works with the R8 compiler. R8 works with all of your existing ProGuard rules files, so updating the Android Gradle plugin to use R8 should not require you to change your existing rules.

R8 is the new code shrinker from Google and was introduced in Android Studio 3.3 beta. By default, R8 removes attributes that are useful for debugging, including line numbers, source file names, and variable names. R8 is a free Java class file shrinker, optimizer, obfuscator, and pre-verifier and is faster than ProGuard, see also an [Android Developer blog post for further details](https://android-developers.googleblog.com/2018/11/r8-new-code-shrinker-from-google-is.html "R8"). It is shipped with Android's SDK tools. To activate shrinking for the release build, add the following to build.gradle:  

```default
android {
    buildTypes {
        release {
            // Enables code shrinking, obfuscation, and optimization for only
            // your project's release build type.
            minifyEnabled true

            // Includes the default ProGuard rules files that are packaged with
            // the Android Gradle plugin. To learn more, go to the section about
            // R8 configuration files.
            proguardFiles getDefaultProguardFile(
                    'proguard-android-optimize.txt'),
                    'proguard-rules.pro'
        }
    }
    ...
}
```

The file `proguard-rules.pro` is where you define custom ProGuard rules. With the flag `-keep` you can keep certain code that is not being removed by R8, which might otherwise produce errors. For example to keep common Android classes, as in our sample configuration `proguard-rules.pro` file:

```default
...
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
...
```

You can define this more granularly on specific classes or libraries in your project with the [following syntax](https://developer.android.com/studio/build/shrink-code#configuration-files "Customize which code to keep"):

```default
-keep public class MyClass
```

Obfuscation often carries a cost in runtime performance, therefore it is usually only applied to certain very specific parts of the code, typically those dealing with security and runtime protection.

### Static Analysis

[Decompile the APK](0x05c-Reverse-Engineering-and-Tampering.md#decompiling-java-code) and [review it](0x05c-Reverse-Engineering-and-Tampering.md#reviewing-decompiled-java-code) to determine whether the codebase has been obfuscated.

Below you can find a sample for an obfuscated code block:

```java
package com.a.a.a;

import com.a.a.b.a;
import java.util.List;

class a$b
  extends a
{
  public a$b(List paramList)
  {
    super(paramList);
  }

  public boolean areAllItemsEnabled()
  {
    return true;
  }

  public boolean isEnabled(int paramInt)
  {
    return true;
  }
}
```

Here are some considerations:

- Meaningful identifiers, such as class names, method names, and variable names, might have been discarded.
- String resources and strings in binaries might have been encrypted.
- Code and data related to the protected functionality might be encrypted, packed, or otherwise concealed.

For native code:

- [libc APIs](https://man7.org/linux/man-pages/dir_section_3.html) (e.g open, read) might have been replaced with OS [syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html).
- [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator "Obfuscator-LLVM") might have been applied to perform ["Control Flow Flattening"](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening) or ["Bogus Control Flow"](https://github.com/obfuscator-llvm/obfuscator/wiki/Bogus-Control-Flow).

Some of these techniques are discussed and analyzed in the blog post ["Security hardening of Android native code"](https://darvincitech.wordpress.com/2020/01/07/security-hardening-of-android-native-code/) by Gautam Arvind and in the ["APKiD: Fast Identification of AppShielding Products"](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf) presentation by Eduardo Novella.

For a more detailed assessment, you need a detailed understanding of the relevant threats and the obfuscation methods used. There are some tools such as [APKiD](0x08-Testing-Tools.md#apkid) that might be able to give you some indications about the kind of techniques were used for the target app such as obfuscators, packers, anti debug.

### Dynamic Analysis

You can use [APKiD](0x08-Testing-Tools.md#apkid) to detect if the app has been obfuscated.

Example using the [Android Crackme Level 4](https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Android/Level_04/r2pay-v1.0.apk):

```sh
apkid owasp-mstg/Crackmes/Android/Level_04/r2pay-v1.0.apk
[+] APKiD 2.1.2 :: from RedNaga :: rednaga.io
[*] owasp-mstg/Crackmes/Android/Level_04/r2pay-v1.0.apk!classes.dex
 |-> anti_vm : Build.TAGS check, possible ro.secure check
 |-> compiler : r8
 |-> obfuscator : unreadable field names, unreadable method names
```

In this case it detects that the app has unreadable field names and method names, among other things.

## Testing Device Binding (MSTG-RESILIENCE-10)

### Overview

The goal of device binding is to impede an attacker who tries to both copy an app and its state from device A to device B and continue executing the app on device B. After device A has been determined trustworthy, it may have more privileges than device B. These differential privileges should not change when an app is copied from device A to device B.

Before we describe the usable identifiers, let's quickly discuss how they can be used for binding. There are three methods that allow device binding:

- Augmenting the credentials used for authentication with device identifiers. This make sense if the application needs to re-authenticate itself and/or the user frequently.

- Encrypting the data stored in the device with the key material which is strongly bound to the device can strengthen the device binding. The Android Keystore offers non-exportable private keys which we can use for this. When a malicious actor would extract such data from a device, it wouldn't be possible to decrypt the data, as the key is not accessible. Implementing this, takes the following steps:

  - Generate the key pair in the Android Keystore using `KeyGenParameterSpec` API.

    ```java
    //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
    keyPairGenerator.initialize(
            new KeyGenParameterSpec.Builder(
                    "key1",
                    KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .build());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    ...

    // The key pair can also be obtained from the Android Keystore any time as follows:
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
    PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();
    ```

  - Generating a secret key for AES-GCM:

    ```java
    //Source: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html>
    KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
    keyGenerator.init(
            new KeyGenParameterSpec.Builder("key2",
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());
    SecretKey key = keyGenerator.generateKey();

    // The key can also be obtained from the Android Keystore any time as follows:
    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    key = (SecretKey) keyStore.getKey("key2", null);
    ```

  - Encrypt the authentication data and other sensitive data stored by the application using a secret key through AES-GCM cipher and use device specific parameters such as Instance ID, etc. as associated data:

    ```java
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final byte[] nonce = new byte[GCM_NONCE_LENGTH];
    random.nextBytes(nonce);
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    byte[] aad = "<deviceidentifierhere>".getBytes();;
    cipher.updateAAD(aad);
    cipher.init(Cipher.ENCRYPT_MODE, key);

    //use the cipher to encrypt the authentication data see 0x50e for more details.
    ```

  - Encrypt the secret key using the public key stored in Android Keystore and store the encrypted secret key in the private storage of the application.
  - Whenever authentication data such as access tokens or other sensitive data is required, decrypt the secret key using private key stored in Android Keystore and then use the decrypted secret key to decrypt the ciphertext.

- Use token-based device authentication (Instance ID) to make sure that the same instance of the app is used.

### Static Analysis

In the past, Android developers often relied on the `Settings.Secure.ANDROID_ID` (SSAID) and MAC addresses. This [changed with the release of Android 8.0 (API level 26)](https://android-developers.googleblog.com/2017/04/changes-to-device-identifiers-in.html "Changes in the Android device identifiers"). As the MAC address is now often randomized when not connected to an access point and the SSAID is no longer a device bound ID. Instead, it became a value bound to the user, the device and the app signing key of the application which requests the SSAID.
In addition, there are new [recommendations for identifiers](https://developer.android.com/training/articles/user-data-ids.html "Developer Android documentation - User data IDs") in Google's SDK documentation. Basically, Google recommends to:

- use the Advertising ID (`AdvertisingIdClient.Info`) when it comes to advertising -so that the user has the option to decline.
- use the Instance ID (`FirebaseInstanceId`) for device identification.
- use the SSAID only for fraud detection and for sharing state between apps signed by the same developer.

Note that the Instance ID and the Advertising ID are not stable across device upgrades and device-resets. However, the Instance ID will at least allow to identify the current software installation on a device.

There are a few key terms you can look for when the source code is available:

- Unique identifiers that will no longer work:
  - `Build.SERIAL` without `Build.getSerial`
  - `htc.camera.sensor.front_SN` for HTC devices
  - `persist.service.bdroid.bdadd`
  - `Settings.Secure.bluetooth_address` or `WifiInfo.getMacAddress` from `WifiManager`, unless the system permission `LOCAL_MAC_ADDRESS` is enabled in the manifest.
- `ANDROID_ID` used only as an identifier. This will influence the binding quality over time for older devices.
- The absence of Instance ID, `Build.SERIAL`, and the IMEI.

```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```

- The creation of private keys in the `AndroidKeyStore` using the `KeyPairGeneratorSpec` or `KeyGenParameterSpec` APIs.

To be sure that the identifiers can be used, check `AndroidManifest.xml` for usage of the IMEI and `Build.Serial`. The file should contain the permission `<uses-permission android:name="android.permission.READ_PHONE_STATE" />`.

> Apps for Android 8.0 (API level 26) will get the result "UNKNOWN" when they request `Build.Serial`.

### Dynamic Analysis

There are several ways to test the application binding:

#### Dynamic Analysis with an Emulator

1. Run the application on an emulator.
2. Make sure you can raise the trust in the application instance (e.g., authenticate in the app).
3. Retrieve the data from the emulator according to the following steps:
   - SSH into your simulator via an ADB shell.
   - Execute `run-as <your app-id>`. Your app-id is the package described in the AndroidManifest.xml.
   - `chmod 777` the contents of cache and shared-preferences.
   - Exit the current user from the the app-id.
   - Copy the contents of `/data/data/<your appid>/cache` and `shared-preferences` to the SD card.
   - Use ADB or the DDMS to pull the contents.
4. Install the application on another emulator.
5. In the application's data folder, overwrite the data from step 3.
   - Copy the data from step 3 to the second emulator's SD card.
   - SSH into your simulator via an ADB shell.
   - Execute `run-as <your app-id>`. Your app-id is the package described in  `AndroidManifest.xml`.
   - `chmod 777` the folder's cache and shared-preferences.
   - Copy the older contents of the SD card `to /data/data/<your appid>/cache` and `shared-preferences`.
6. Can you continue in an authenticated state? If so, binding may not be working properly.

#### Google Instance ID

[Google Instance ID](https://developers.google.com/instance-id/ "Google Instance ID documentation") uses tokens to authenticate the running application instance. The moment the application is reset, uninstalled, etc., the Instance ID is reset, meaning that you'll have a new "instance" of the app.
Go through the following steps for Instance ID:

1. Configure your Instance ID for the given application in your Google Developer Console. This includes managing the PROJECT_ID.

2. Setup Google Play services. In the file `build.gradle`, add

    ```default
    apply plugin: 'com.android.application'
        ...

        dependencies {
            compile 'com.google.android.gms:play-services-gcm:10.2.4'
        }
    ```

3. Get an Instance ID.

    ```java
    String iid = Instance ID.getInstance(context).getId();
    //now submit this iid to your server.
    ```

4. Generate a token.

    ```java
    String authorizedEntity = PROJECT_ID; // Project id from Google Developer Console
    String scope = "GCM"; // e.g. communicating using GCM, but you can use any
                        // URL-safe characters up to a maximum of 1000, or
                        // you can also leave it blank.
    String token = Instance ID.getInstance(context).getToken(authorizedEntity,scope);
    //now submit this token to the server.
    ```

5. Make sure that you can handle callbacks from Instance ID, in case of invalid device information, security issues, etc. This requires extending `Instance IDListenerService` and handling the callbacks there:

    ```java
    public class MyInstance IDService extends Instance IDListenerService {
    public void onTokenRefresh() {
        refreshAllTokens();
    }

    private void refreshAllTokens() {
        // assuming you have defined TokenList as
        // some generalized store for your tokens for the different scopes.
        // Please note that for application validation having just one token with one scopes can be enough.
        ArrayList<TokenList> tokenList = TokensList.get();
        Instance ID iid = Instance ID.getInstance(this);
        for(tokenItem : tokenList) {
        tokenItem.token =
            iid.getToken(tokenItem.authorizedEntity,tokenItem.scope,tokenItem.options);
        // send this tokenItem.token to your server
        }
    }
    };

    ```

6. Register the service in your Android manifest:

    ```xml
    <service android:name=".MyInstance IDService" android:exported="false">
    <intent-filter>
            <action android:name="com.google.android.gms.iid.Instance ID" />
    </intent-filter>
    </service>
    ```

When you submit the Instance ID (iid) and the tokens to your server, you can use that server with the Instance ID Cloud Service to validate the tokens and the iid. When the iid or token seems invalid, you can trigger a safeguard procedure (e.g., informing the server of possible copying or security issues or removing the data from the app and asking for a re-registration).

Please note that [Firebase also supports Instance ID](https://firebase.google.com/docs/reference/android/com/google/firebase/iid/FirebaseInstanceId "Firebase Instance ID documentation").

#### IMEI & Serial

Google recommends not using these identifiers unless the application is at a high risk.

For Android devices before Android 8.0 (API level 26), you can request the serial as follows:

```java
   String serial = android.os.Build.SERIAL;
```

For devices running Android version O and later, you can request the device's serial as follows:

1. Set the permission in your Android manifest:

    ```xml
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    ```

2. Request the permission at runtime from the user: See [https://developer.android.com/training/permissions/requesting.html](https://developer.android.com/training/permissions/requesting.html "Request App Permissions") for more details.
3. Get the serial:

    ```java
    String serial = android.os.Build.getSerial();
    ```

Retrieve the IMEI:

1. Set the required permission in your Android manifest:

    ```xml
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    ```

2. If you're using Android version Android 6 (API level 23) or later, request the permission at runtime from the user: See [https://developer.android.com/training/permissions/requesting.html](https://developer.android.com/training/permissions/requesting.html "Request App Permissions") for more details.

3. Get the IMEI:

    ```java
    TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
    String IMEI = tm.getDeviceId();
    ```

#### SSAID

Google recommends not using these identifiers unless the application is at a high risk. You can retrieve the SSAID as follows:

```java
  String SSAID = Settings.Secure.ANDROID_ID;
```

The behavior of the SSAID and MAC addresses have [changed since Android 8.0 (API level 26)](https://android-developers.googleblog.com/2017/04/changes-to-device-identifiers-in.html "Changes in the Android device identifiers"). In addition, there are [new recommendations](https://developer.android.com/training/articles/user-data-ids.html "Developer Android documentation") for identifiers in Google's SDK documentation. Because of this new behavior, we recommend that developers not rely on the SSAID alone. The identifier has become less stable. For example, the SSAID may change after a factory reset or when the app is reinstalled after the upgrade to Android 8.0 (API level 26). There are devices that have the same `ANDROID_ID` and/or have an `ANDROID_ID` that can be overridden. Therefore it is better to encrypt the `ANDROID_ID` with a randomly generated key from the `AndroidKeyStore` using `AES_GCM` encryption. The encrypted `ANDROID_ID` should then be stored in the `SharedPreferences` (privately). The moment the app-signature changes, the application can check for a delta and register the new `ANDROID_ID`. The moment this changes without a new application signing key, it should indicate that something else is wrong.

### Effectiveness Assessment

There are a few key terms you can look for when the source code is available:

- Unique identifiers that will no longer work:
  - `Build.SERIAL` without `Build.getSerial`
  - `htc.camera.sensor.front_SN` for HTC devices
  - `persist.service.bdroid.bdadd`
  - `Settings.Secure.bluetooth_address` or `WifiInfo.getMacAddress` from `WifiManager`, unless the system permission `LOCAL_MAC_ADDRESS` is enabled in the manifest.

- Usage of ANDROID_ID as an identifier only. Over time, this will influence the binding quality on older devices.
- The absence of Instance ID, `Build.SERIAL`, and the IMEI.

```java
  TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
  String IMEI = tm.getDeviceId();
```

To make sure that the identifiers can be used, check `AndroidManifest.xml` for usage of the IMEI and `Build.Serial`. The manifest should contain the permission `<uses-permission android:name="android.permission.READ_PHONE_STATE" />`.

There are a few ways to test device binding dynamically:

#### Using an Emulator

See section "[Dynamic Analysis with an Emulator](#dynamic-analysis-with-an-emulator "Dynamic Analysis with an Emulator")" above.

#### Using two different rooted devices

1. Run the application on your rooted device.
2. Make sure you can raise the trust (e.g., authenticate in the app) in the application instance.
3. Retrieve the data from the first rooted device.
4. Install the application on the second rooted device.
5. In the application's data folder, overwrite the data from step 3.
6. Can you continue in an authenticated state? If so, binding may not be working properly.

## References

### OWASP MASVS

- MSTG-RESILIENCE-1: "The app detects, and responds to, the presence of a rooted or jailbroken device either by alerting the user or terminating the app."
- MSTG-RESILIENCE-2: "The app prevents debugging and/or detects, and responds to, a debugger being attached. All available debugging protocols must be covered."
- MSTG-RESILIENCE-3: "The app detects, and responds to, tampering with executable files and critical data within its own sandbox."
- MSTG-RESILIENCE-4: "The app detects, and responds to, the presence of widely used reverse engineering tools and frameworks on the device."
- MSTG-RESILIENCE-5: "The app detects, and responds to, being run in an emulator."
- MSTG-RESILIENCE-6: "The app detects, and responds to, tampering the code and data in its own memory space."
- MSTG-RESILIENCE-9: "Obfuscation is applied to programmatic defenses, which in turn impede de-obfuscation via dynamic analysis."
- MSTG-RESILIENCE-10: "The app implements a 'device binding' functionality using a device fingerprint derived from multiple properties unique to the device."

### SafetyNet Attestation

- Developer Guideline - <https://developer.android.com/training/safetynet/attestation.html>
- SafetyNet Attestation Checklist - <https://developer.android.com/training/safetynet/attestation-checklist>
- Do's & Don'ts of SafetyNet Attestation - <https://android-developers.googleblog.com/2017/11/10-things-you-might-be-doing-wrong-when.html>
- SafetyNet Verification Samples - <https://github.com/googlesamples/android-play-safetynet/>
- SafetyNet Attestation API - Quota Request - <https://support.google.com/googleplay/android-developer/contact/safetynetqr>
- Obfuscator-LLVM - <https://github.com/obfuscator-llvm/obfuscator>
