---
title: radare2 for Android
platform: android
source: https://github.com/radare/radare2
---

[radare2](https://rada.re/r/ "Radare2 official website") (r2) is a popular open source reverse engineering framework for disassembling, debugging, patching and analyzing binaries that is scriptable and supports many architectures and file formats including Android and iOS apps. For Android, Dalvik DEX (odex, multidex), ELF (executables, .so, ART) and Java (JNI and Java classes) are supported. It also contains several useful scripts that can help you during mobile application analysis as it offers low level disassembling and safe static analysis that comes in handy when traditional tools fail.

radare2 implements a rich command line interface (CLI) where you can perform the mentioned tasks. However, if you're not really comfortable using the CLI for reverse engineering you may want to consider using the Web UI (via the `-H` flag) or the even more convenient Qt and C++ GUI version called [iaito](https://github.com/radareorg/iaito "iaito"). Do keep in mind that the CLI, and more concretely its Visual Mode and its scripting capabilities ([r2pipe](https://github.com/radare/radare2-r2pipe "r2pipe")), are the core of radare2's power and it's definitely worth learning how to use it.

## Installing radare2

Please refer to [radare2's official installation instructions](https://github.com/radare/radare2/blob/master/README.md "radare2 installation instructions"). We highly recommend to always install radare2 from the GitHub version instead of via common package managers such as APT. Radare2 is in very active development, which means that third party repositories are often outdated.

## Using radare2

The radare2 framework comprises a set of small utilities that can be used from the r2 shell or independently as CLI tools. These utilities include `rabin2`, `rasm2`, `rahash2`, `radiff2`, `rafind2`, `ragg2`, `rarun2`, `rax2`, and of course `r2`, which is the main one.

For example, you can use `rafind2` to read strings directly from an encoded Android Manifest (AndroidManifest.xml):

```bash
# Permissions
$ rafind2 -ZS permission AndroidManifest.xml
# Activities
$ rafind2 -ZS activity AndroidManifest.xml
# Content providers
$ rafind2 -ZS provider AndroidManifest.xml
# Services
$ rafind2 -ZS service AndroidManifest.xml
# Receivers
$ rafind2 -ZS receiver AndroidManifest.xml
```

Or use `rabin2` to get information about a binary file:

```bash
$ rabin2 -I UnCrackable-Level1/classes.dex
arch     dalvik
baddr    0x0
binsz    5528
bintype  class
bits     32
canary   false
retguard false
class    035
crypto   false
endian   little
havecode true
laddr    0x0
lang     dalvik
linenum  false
lsyms    false
machine  Dalvik VM
maxopsz  16
minopsz  1
nx       false
os       linux
pcalign  0
pic      false
relocs   false
sanitiz  false
static   true
stripped false
subsys   java
va       true
sha1  12-5508c  b7fafe72cb521450c4470043caa332da61d1bec7
adler32  12-5528c  00000000
```

Type `rabin2 -h` to see all options:

```bash
$ rabin2 -h
Usage: rabin2 [-AcdeEghHiIjlLMqrRsSUvVxzZ] [-@ at] [-a arch] [-b bits] [-B addr]
              [-C F:C:D] [-f str] [-m addr] [-n str] [-N m:M] [-P[-P] pdb]
              [-o str] [-O str] [-k query] [-D lang symname] file
 -@ [addr]       show section, symbol or import at addr
 -A              list sub-binaries and their arch-bits pairs
 -a [arch]       set arch (x86, arm, .. or <arch>_<bits>)
 -b [bits]       set bits (32, 64 ...)
 -B [addr]       override base address (pie bins)
 -c              list classes
 -cc             list classes in header format
 -H              header fields
 -i              imports (symbols imported from libraries)
 -I              binary info
 -j              output in json
 ...
```

Use the main `r2` utility to access the **r2 shell**. You can load DEX binaries just like any other binary:

```bash
r2 classes.dex
```

Enter `r2 -h` to see all available options. A very commonly used flag is `-A`, which triggers an analysis after loading the target binary. However, this should be used sparingly and with small binaries as it is very time and resource consuming. You can learn more about this in the chapter "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)".

Once in the r2 shell, you can also access functions offered by the other radare2 utilities. For example, running `i` will print the information of the binary, exactly as `rabin2 -I` does.

To print all the strings use `rabin2 -Z` or the command `iz` (or the less verbose `izq`) from the r2 shell.

```bash
[0x000009c8]> izq
0xc50 39 39 /dev/com.koushikdutta.superuser.daemon/
0xc79 25 25 /system/app/Superuser.apk
...
0xd23 44 44 5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=
0xd51 32 32 8d127684cbc37c17616d806cf50473cc
0xd76 6 6 <init>
0xd83 10 10 AES error:
0xd8f 20 20 AES/ECB/PKCS7Padding
0xda5 18 18 App is debuggable!
0xdc0 9 9 CodeCheck
0x11ac 7 7 Nope...
0x11bf 14 14 Root detected!
```

Most of the time you can append special options to your commands such as `q` to make the command less verbose (quiet) or `j` to give the output in JSON format (use `~{}` to prettify the JSON string).

```bash
[0x000009c8]> izj~{}
[
  {
    "vaddr": 3152,
    "paddr": 3152,
    "ordinal": 1,
    "size": 39,
    "length": 39,
    "section": "file",
    "type": "ascii",
    "string": "L2Rldi9jb20ua291c2hpa2R1dHRhLnN1cGVydXNlci5kYWVtb24v"
  },
  {
    "vaddr": 3193,
    "paddr": 3193,
    "ordinal": 2,
    "size": 25,
    "length": 25,
    "section": "file",
    "type": "ascii",
    "string": "L3N5c3RlbS9hcHAvU3VwZXJ1c2VyLmFwaw=="
  },
```

You can print the class names and their methods with the r2 command `ic` (_information classes_).

```bash
[0x000009c8]> ic
...
0x0000073c [0x00000958 - 0x00000abc]    356 class 5 Lsg/vantagepoint/uncrackable1/MainActivity
:: Landroid/app/Activity;
0x00000958 method 0 pC   Lsg/vantagepoint/uncrackable1/MainActivity.method.<init>()V
0x00000970 method 1 P    Lsg/vantagepoint/uncrackable1/MainActivity.method.a(Ljava/lang/String;)V
0x000009c8 method 2 r    Lsg/vantagepoint/uncrackable1/MainActivity.method.onCreate (Landroid/os/Bundle;)V
0x00000a38 method 3 p    Lsg/vantagepoint/uncrackable1/MainActivity.method.verify (Landroid/view/View;)V
0x0000075c [0x00000acc - 0x00000bb2]    230 class 6 Lsg/vantagepoint/uncrackable1/a :: Ljava/lang/Object;
0x00000acc method 0 sp   Lsg/vantagepoint/uncrackable1/a.method.a(Ljava/lang/String;)Z
0x00000b5c method 1 sp   Lsg/vantagepoint/uncrackable1/a.method.b(Ljava/lang/String;)[B
```

You can print the imported methods with the r2 command `ii` (_information imports_).

```bash
[0x000009c8]> ii
[Imports]
Num  Vaddr       Bind      Type Name
...
  29 0x000005cc    NONE    FUNC Ljava/lang/StringBuilder.method.append(Ljava/lang/String;) Ljava/lang/StringBuilder;
  30 0x000005d4    NONE    FUNC Ljava/lang/StringBuilder.method.toString()Ljava/lang/String;
  31 0x000005dc    NONE    FUNC Ljava/lang/System.method.exit(I)V
  32 0x000005e4    NONE    FUNC Ljava/lang/System.method.getenv(Ljava/lang/String;)Ljava/lang/String;
  33 0x000005ec    NONE    FUNC Ljavax/crypto/Cipher.method.doFinal([B)[B
  34 0x000005f4    NONE    FUNC Ljavax/crypto/Cipher.method.getInstance(Ljava/lang/String;) Ljavax/crypto/Cipher;
  35 0x000005fc    NONE    FUNC Ljavax/crypto/Cipher.method.init(ILjava/security/Key;)V
  36 0x00000604    NONE    FUNC Ljavax/crypto/spec/SecretKeySpec.method.<init>([BLjava/lang/String;)V
```

A common approach when inspecting a binary is to search for something, navigate to it and visualize it in order to interpret the code. One of the ways to find something using radare2 is by filtering the output of specific commands, i.e. to grep them using `~` plus a keyword (`~+` for case-insensitive). For example, we might know that the app is verifying something, we can inspect all radare2 flags and see where we find something related to "verify".

> When loading a file, radare2 tags everything it's able to find. These tagged names or references are called flags. You can access them via the command `f`.

In this case we will grep the flags using the keyword "verify":

```bash
[0x000009c8]> f~+verify
0x00000a38 132 sym.Lsg_vantagepoint_uncrackable1_MainActivity.method. \
verify_Landroid_view_View__V
0x00000a38 132 method.public.Lsg_vantagepoint_uncrackable1_MainActivity. \
Lsg_vantagepoint_uncrackable1
        _MainActivity.method.verify_Landroid_view_View__V
0x00001400 6 str.verify
```

It seems that we've found one method in 0x00000a38 (that was tagged two times) and one string in 0x00001400. Let's navigate (seek) to that method by using its flag:

```bash
[0x000009c8]> s sym.Lsg_vantagepoint_uncrackable1_MainActivity.method. \
verify_Landroid_view_View__V
```

And of course you can also use the disassembler capabilities of r2 and print the disassembly with the command `pd` (or `pdf` if you know you're already located in a function).

```bash
[0x00000a38]> pd
```

r2 commands normally accept options (see `pd?`), e.g. you can limit the opcodes displayed by appending a number ("N") to the command `pd N`.

<img src="Images/Chapters/0x05b/r2_pd_10.png" width="100%" />

Instead of just printing the disassembly to the console you may want to enter the so-called **Visual Mode** by typing `V`.

<img src="Images/Chapters/0x05b/r2_visualmode_hex.png" width="100%" />

By default, you will see the hexadecimal view. By typing `p` you can switch to different views, such as the disassembly view:

<img src="Images/Chapters/0x05b/r2_visualmode_disass.png" width="100%" />

Radare2 offers a **Graph Mode** that is very useful to follow the flow of the code. You can access it from the Visual Mode by typing `V`:

<img src="Images/Chapters/0x05b/r2_graphmode.png" width="100%" />

This is only a selection of some radare2 commands to start getting some basic information from Android binaries. Radare2 is very powerful and has dozens of commands that you can find on the [radare2 command documentation](https://book.rada.re/basic_commands/intro.html "radare2 command documentation"). Radare2 will be used throughout the guide for different purposes such as reversing code, debugging or performing binary analysis. We will also use it in combination with other frameworks, especially Frida (see the r2frida section for more information).

Please refer to the chapter "[Tampering and Reverse Engineering on Android](0x05c-Reverse-Engineering-and-Tampering.md)" for more detailed use of radare2 on Android, especially when analyzing native libraries. You may also want to read the [official radare2 book](https://book.rada.re/ "Radare2 book").
