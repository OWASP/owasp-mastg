---
masvs_v1_id:
- MSTG-CODE-2
masvs_v2_id:
- MASVS-RESILIENCE-4
platform: android
title: Testing whether the App is Debuggable
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0226,MASTG-TEST-0227]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

Check `AndroidManifest.xml` to determine whether the `android:debuggable` attribute has been set and to find the attribute's value:

```xml
    ...
    <application android:allowBackup="true" android:debuggable="true" android:icon="@drawable/ic_launcher" android:label="@string/app_name" android:theme="@style/AppTheme">
    ...
```

You can use `aapt` tool from the Android SDK with the following command line to quickly check if the `android:debuggable="true"` directive is present:

```bash
# If the command print 1 then the directive is present
# The regex search for this line: android:debuggable(0x0101000f)=(type 0x12)0xffffffff
$ aapt d xmltree sieve.apk AndroidManifest.xml | grep -Ec "android:debuggable\(0x[0-9a-f]+\)=\(type\s0x[0-9a-f]+\)0xffffffff"
1
```

For a release build, this attribute should always be set to `"false"` (the default value).

## Dynamic Analysis

`adb` can be used to determine whether an application is debuggable.

Use the following command:

```bash
# If the command print a number superior to zero then the application have the debug flag
# The regex search for these lines:
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
# pkgFlags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
$ adb shell dumpsys package com.mwr.example.sieve | grep -c "DEBUGGABLE"
2
$ adb shell dumpsys package com.nondebuggableapp | grep -c "DEBUGGABLE"
0
```

If an application is debuggable, executing application commands is trivial. In the `adb` shell, execute `run-as` by appending the package name and application command to the binary name:

```bash
$ run-as com.vulnerable.app id
uid=10084(u0_a84) gid=10084(u0_a84) groups=10083(u0_a83),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:untrusted_app:s0:c512,c768
```

[Android Studio](https://developer.android.com/tools/debugging/debugging-studio.html "Debugging with Android Studio") can also be used to debug an application and verify debugging activation for an app.

Another method for determining whether an application is debuggable is attaching `jdb` to the running process. If this is successful, debugging will be activated.

The following procedure can be used to start a debug session with `jdb`:

1. Using `adb` and `jdwp`, identify the PID of the active application that you want to debug:

    ```bash
    $ adb jdwp
    2355
    16346  <== last launched, corresponds to our application
    ```

2. Create a communication channel by using `adb` between the application process (with the PID) and your host computer by using a specific local port:

    ```bash
    # adb forward tcp:[LOCAL_PORT] jdwp:[APPLICATION_PID]
    $ adb forward tcp:55555 jdwp:16346
    ```

3. Using `jdb`, attach the debugger to the local communication channel port and start a debug session:

    ```bash
    $ jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=55555
    Set uncaught java.lang.Throwable
    Set deferred uncaught java.lang.Throwable
    Initializing jdb ...
    > help
    ```

A few notes about debugging:

- @MASTG-TOOL-0018 can be used to identify interesting locations for breakpoint insertion.
- Usage of basic commands for jdb can be found at [Tutorialspoint](https://www.tutorialspoint.com/jdb/jdb_basic_commands.htm "jdb basic commands").
- If you get an error telling that "the connection to the debugger has been closed" while `jdb` is being bound to the local communication channel port, kill all adb sessions and start a single new session.
