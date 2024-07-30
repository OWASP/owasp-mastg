---
title: Get Open Files
platform: ios
---

`lsof` is a powerful command, and provides a plethora of information about a running process. It can provide a list of all open files, including a stream, a network file or a regular file. When invoking the `lsof` command without any option it will list all open files belonging to all active processes on the system, while when invoking with the flags `-c <process name>` or `-p <pid>`, it returns the list of open files for the specified process. The [man page](http://man7.org/linux/man-pages/man8/lsof.8.html "Man Page of lsof") shows various other options in detail.

Using `lsof` for an iOS application running with PID 2828, list various open files as shown below.

```bash
iPhone:~ root# lsof -p 2828
COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME
iOweApp 2828 mobile  cwd    DIR    1,2      864      2 /
iOweApp 2828 mobile  txt    REG    1,3   206144 189774 /private/var/containers/Bundle/Application/F390A491-3524-40EA-B3F8-6C1FA105A23A/iOweApp.app/iOweApp
iOweApp 2828 mobile  txt    REG    1,3     5492 213230 /private/var/mobile/Containers/Data/Application/5AB3E437-9E2D-4F04-BD2B-972F6055699E/tmp/com.apple.dyld/iOweApp-6346DC276FE6865055F1194368EC73CC72E4C5224537F7F23DF19314CF6FD8AA.closure
iOweApp 2828 mobile  txt    REG    1,3    30628 212198 /private/var/preferences/Logging/.plist-cache.vqXhr1EE
iOweApp 2828 mobile  txt    REG    1,2    50080 234433 /usr/lib/libobjc-trampolines.dylib
iOweApp 2828 mobile  txt    REG    1,2   344204  74185 /System/Library/Fonts/AppFonts/ChalkboardSE.ttc
iOweApp 2828 mobile  txt    REG    1,2   664848 234595 /usr/lib/dyld
...
```
