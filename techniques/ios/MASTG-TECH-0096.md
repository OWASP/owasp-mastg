---
title: Process Exploration
platform: ios
---

When testing an app, process exploration can provide the tester with deep insights into the app process memory. It can be achieved via runtime instrumentation and allows to perform tasks such as:

- Retrieving the memory map and loaded libraries.
- Searching for occurrences of certain data.
- After doing a search, obtaining the location of a certain offset in the memory map.
- Performing a memory dump and inspect or reverse engineer the binary data _offline_.
- Reverse engineering a binary or Framework while it's running.

As you can see, these tasks are rather supportive and/or passive, they'll help us collect data and information that will support other techniques. Therefore, they're normally used in combination with other techniques such as method hooking.

In the following sections you will be using [r2frida](0x08a-Testing-Tools.md#r2frida) to retrieve information straight from the app runtime. First start by opening an r2frida session to the target app (e.g. [iGoat-Swift](0x08b-Reference-Apps.md#igoat-swift)) that should be running on your iPhone (connected per USB). Use the following command:

```bash
r2 frida://usb//iGoat-Swift
```

## Memory Maps and Inspection

You can retrieve the app's memory maps by running `\dm`:

```bash
[0x00000000]> \dm
0x0000000100b7c000 - 0x0000000100de0000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
0x0000000100de0000 - 0x0000000100e68000 rw- /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
0x0000000100e68000 - 0x0000000100e97000 r-- /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
...
0x0000000100ea8000 - 0x0000000100eb0000 rw-
0x0000000100eb0000 - 0x0000000100eb4000 r--
0x0000000100eb4000 - 0x0000000100eb8000 r-x /usr/lib/TweakInject.dylib
0x0000000100eb8000 - 0x0000000100ebc000 rw- /usr/lib/TweakInject.dylib
0x0000000100ebc000 - 0x0000000100ec0000 r-- /usr/lib/TweakInject.dylib
0x0000000100f60000 - 0x00000001012dc000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/Frameworks/Realm.framework/Realm
```

While you're searching or exploring the app memory, you can always verify where your current offset is located in the memory map. Instead of noting and searching for the memory address in this list you can simply run `\dm.`. You'll find an example in the following section "In-Memory Search".

If you're only interested into the modules (binaries and libraries) that the app has loaded, you can use the command `\il` to list them all:

```bash
[0x00000000]> \il
0x0000000100b7c000 iGoat-Swift
0x0000000100eb4000 TweakInject.dylib
0x00000001862c0000 SystemConfiguration
0x00000001847c0000 libc++.1.dylib
0x0000000185ed9000 Foundation
0x000000018483c000 libobjc.A.dylib
0x00000001847be000 libSystem.B.dylib
0x0000000185b77000 CFNetwork
0x0000000187d64000 CoreData
0x00000001854b4000 CoreFoundation
0x00000001861d3000 Security
0x000000018ea1d000 UIKit
0x0000000100f60000 Realm
```

As you might expect you can correlate the addresses of the libraries with the memory maps: e.g. the main app binary [iGoat-Swift](0x08b-Reference-Apps.md#igoat-swift) is located at `0x0000000100b7c000` and the Realm Framework at `0x0000000100f60000`.

You can also use objection to display the same information.

```bash
$ objection --gadget OWASP.iGoat-Swift explore

OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # memory list modules
Save the output by adding `--json modules.json` to this command

Name                              Base         Size                  Path
--------------------------------  -----------  --------------------  ------------------------------------------------------------------------------
iGoat-Swift                       0x100b7c000  2506752 (2.4 MiB)     /var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGo...
TweakInject.dylib                 0x100eb4000  16384 (16.0 KiB)      /usr/lib/TweakInject.dylib
SystemConfiguration               0x1862c0000  446464 (436.0 KiB)    /System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguratio...
libc++.1.dylib                    0x1847c0000  368640 (360.0 KiB)    /usr/lib/libc++.1.dylib
```

## In-Memory Search

In-memory search is a very useful technique to test for sensitive data that might be present in the app memory.

See r2frida's help on the search command (`\/?`) to learn about the search command and get a list of options. The following shows only a subset of them:

```bash
[0x00000000]> \/?
 /      search
 /j     search json
 /w     search wide
 /wj    search wide json
 /x     search hex
 /xj    search hex json
...
```

You can adjust your search by using the search settings `\e~search`. For example, `\e search.quiet=true;` will print only the results and hide search progress:

```bash
[0x00000000]> \e~search
e search.in=perm:r--
e search.quiet=false
```

For now, we'll continue with the defaults and concentrate on string search. In this first example, you can start by searching for something that you know should be located in the main binary of the app:

```bash
[0x00000000]> \/ iGoat
Searching 5 bytes: 69 47 6f 61 74
Searching 5 bytes in [0x0000000100b7c000-0x0000000100de0000]
...
hits: 509
0x100d7d332 hit2_0 iGoat_Swift24StringAnalysisExerciseVCC
0x100d7d3b2 hit2_1 iGoat_Swift28BrokenCryptographyExerciseVCC
0x100d7d442 hit2_2 iGoat_Swift23BackgroundingExerciseVCC
0x100d7d4b2 hit2_3 iGoat_Swift9AboutCellC
0x100d7d522 hit2_4 iGoat_Swift12FadeAnimatorV
```

Now take the first hit, seek to it and check your current location in the memory map:

```bash
[0x00000000]> s 0x100d7d332
[0x100d7d332]> \dm.
0x0000000100b7c000 - 0x0000000100de0000 r-x /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app/iGoat-Swift
```

As expected, you are located in the region of the main [iGoat-Swift](0x08b-Reference-Apps.md#igoat-swift) binary (r-x, read and execute). In the previous section, you saw that the main binary is located between `0x0000000100b7c000` and `0x0000000100e97000`.

Now, for this second example, you can search for something that's not in the app binary nor in any loaded library, typically user input. Open the [iGoat-Swift](0x08b-Reference-Apps.md#igoat-swift) app and navigate in the menu to **Authentication** -> **Remote Authentication** -> **Start**. There you'll find a password field that you can overwrite. Write the string "owasp-mstg" but do not click on **Login** just yet. Perform the following two steps.

```bash
[0x00000000]> \/ owasp-mstg
hits: 1
0x1c06619c0 hit3_0 owasp-mstg
```

In fact, the string could be found at address `0x1c06619c0`. Seek `s` to there and retrieve the current memory region with `\dm.`.

```bash
[0x100d7d332]> s 0x1c06619c0
[0x1c06619c0]> \dm.
0x00000001c0000000 - 0x00000001c8000000 rw-
```

Now you know that the string is located in a rw- (read and write) region of the memory map.

Additionally, you can search for occurrences of the [wide version of the string](https://en.wikipedia.org/wiki/Wide_character "Wide character") (`/w`) and, again, check their memory regions:

> This time we run the `\dm.` command for all `@@` hits matching the glob `hit5_*`.

```bash
[0x00000000]> /w owasp-mstg
Searching 20 bytes: 6f 00 77 00 61 00 73 00 70 00 2d 00 6d 00 73 00 74 00 67 00
Searching 20 bytes in [0x0000000100708000-0x000000010096c000]
...
hits: 2
0x1020d1280 hit5_0 6f0077006100730070002d006d00730074006700
0x1030c9c85 hit5_1 6f0077006100730070002d006d00730074006700

[0x00000000]> \dm.@@ hit5_*
0x0000000102000000 - 0x0000000102100000 rw-
0x0000000103084000 - 0x00000001030cc000 rw-
```

They are in a different rw- region. Note that searching for the wide versions of strings is sometimes the only way to find them as you'll see in the following section.

In-memory search can be very useful to quickly know if certain data is located in the main app binary, inside a shared library or in another region. You may also use it to test the behavior of the app regarding how the data is kept in memory. For instance, you could continue the previous example, this time clicking on Login and searching again for occurrences of the data. Also, you may check if you still can find those strings in memory after the login is completed to verify if this _sensitive data_ is wiped from memory after its use.

## Memory Dump

You can dump the app's process memory with [objection](0x08a-Testing-Tools.md#objection) and [Fridump](https://github.com/Nightbringer21/fridump "Fridump"). To take advantage of these tools on a non-jailbroken device, the Android app must be repackaged with `frida-gadget.so` and re-signed. A detailed explanation of this process is in the section "[Dynamic Analysis on Non-Jailbroken Devices](#dynamic-analysis-on-non-jailbroken-devices "Dynamic Analysis on Non-Jailbroken Devices"). To use these tools on a jailbroken phone, simply have frida-server installed and running.

With objection it is possible to dump all memory of the running process on the device by using the command `memory dump all`.

```bash
$ objection explore

iPhone on (iPhone: 10.3.1) [usb] # memory dump all /Users/foo/memory_iOS/memory
Dumping 768.0 KiB from base: 0x1ad200000  [####################################]  100%
Memory dumped to file: /Users/foo/memory_iOS/memory
```

Alternatively you can use Fridump. First, you need the name of the app you want to dump, which you can get with `frida-ps`.

```bash
$ frida-ps -U
 PID  Name
----  ------
1026  Gadget
```

Afterwards, specify the app name in Fridump.

```bash
$ python3 fridump.py -u Gadget -s

Current Directory: /Users/foo/PentestTools/iOS/fridump
Output directory is set to: /Users/foo/PentestTools/iOS/fridump/dump
Creating directory...
Starting Memory dump...
Progress: [##################################################] 100.0% Complete

Running strings on all files:
Progress: [##################################################] 100.0% Complete

Finished! Press Ctrl+C
```

When you add the `-s` flag, all strings are extracted from the dumped raw memory files and added to the file `strings.txt`, which is stored in Fridump's dump directory.

In both cases, if you open the file in radare2 you can use its search command (`/`). Note that first we do a standard string search which doesn't succeed and next we search for a [wide string](https://en.wikipedia.org/wiki/Wide_character "Wide character"), which successfully finds our string "owasp-mstg".

```bash
$ r2 memory_ios
[0x00000000]> / owasp-mstg
Searching 10 bytes in [0x0-0x628c000]
hits: 0
[0x00000000]> /w owasp-mstg
Searching 20 bytes in [0x0-0x628c000]
hits: 1
0x0036f800 hit4_0 6f0077006100730070002d006d00730074006700
```

Next, we can seek to its address using `s 0x0036f800`  or `s hit4_0` and print it using `psw` (which stands for _print string wide_) or use `px` to print its raw hexadecimal values:

```bash
[0x0036f800]> psw
owasp-mstg

[0x0036f800]> px 48
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0036f800  6f00 7700 6100 7300 7000 2d00 6d00 7300  o.w.a.s.p.-.m.s.
0x0036f810  7400 6700 0000 0000 0000 0000 0000 0000  t.g.............
0x0036f820  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Note that in order to find this string using the `strings` command you'll have to specify an encoding using the `-e` flag and in this case `l` for 16-bit little-endian character.

```bash
$ strings -e l memory_ios | grep owasp-mstg
owasp-mstg
```
