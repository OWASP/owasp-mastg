# Android Crackmes

## Android UnCrackable L1

A secret string is hidden somewhere in this app. Find a way to extract it.

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk" class="mas-chip">Download</a>

??? info "Installation"
    This app is compatible with Android 4.4 and up.

    ```shell
    $ adb install UnCrackable-Level1.apk
    ```

??? danger "SPOILER (Solutions)"
    - [Solution using Frida by c0dmtr1x](https://www.codemetrix.net/hacking-android-apps-with-frida-2/ "Solution by c0dmtr1x")
    - [Solution using static analysis](https://mas.owasp.org/MASTG/Android/0x05c-Reverse-Engineering-and-Tampering#reviewing-decompiled-java-code "Solution using static analysis")
    - [Solution using jdb](https://mas.owasp.org/MASTG/Android/0x05c-Reverse-Engineering-and-Tampering#debugging-with-jdb "Solution using jdb")
    - [Solution using Frida by Eduardo Novella](https://enovella.github.io/android/reverse/2017/05/18/android-owasp-crackmes-level-1.html "Solution by Eduardo Novella")
    - [Solution using Xposed by sh3llc0d3r](https://web.archive.org/web/20210124161121/http://sh3llc0d3r.com/owasp-uncrackable-android-level1/ "Solution by sh3llc0d3r")
    - [Solution using RMS by @mobilesecurity_ (video)](https://youtu.be/P6rNPkM2DdY "Solution by @mobilesecurity_")
    - [Solution using static analysis by Eduardo Vasconcelos](https://tereresecurity.wordpress.com/2021/03/03/write-up-uncrackable-level-1/ "Solution by Eduardo Vasconcelos")
    - [Solution using Frida by Davide Cioccia](https://1337.dcodx.com/mobile-security/owasp-mstg-crackme-1-writeup-android "Solution by Davide Cioccia")
    - [Solution using MobSF by Jitendra Patro](https://blog.jitendrapatro.me/owasp-android-uncrackable-level-1/ "Solution by Jitendra Patro")

<i style="color:gray">
By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller")
</i>

## Android UnCrackable L2

This app holds a secret inside. May include traces of native code.

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_02/UnCrackable-Level2.apk" class="mas-chip">Download</a>

??? info "Installation"
    This app is compatible with Android 4.4 and up.

    ```shell
    $ adb install UnCrackable-Level2.apk
    ```

??? danger "SPOILER (Solutions)"
    - [Solution using Frida and radare2 by c0dmtr1x](https://www.codemetrix.net/hacking-android-apps-with-frida-3/ "Solution by c0dmtr1x").
    - [Solution using Frida by Eduardo Novella](https://enovella.github.io/android/reverse/2017/05/20/android-owasp-crackmes-level-2.html "Solution by Eduardo Novella").
    - [Solution using patches by sh3llc0d3r](https://web.archive.org/web/20210124162744/http://sh3llc0d3r.com/owasp-uncrackable-android-level2/ "Solution by sh3llc0d3r").
    - [Solution using RMS by @mobilesecurity_ (video)](https://youtu.be/xRQVljerl0A "Solution by @mobilesecurity_").
    - [Solution using static analysis and Ghidra by Eduardo Vasconcelos](https://tereresecurity.wordpress.com/2021/03/23/write-up-uncrackable-level-2/ "Solution by Eduardo Vasconcelos").
    - [Solution using Ghidra and Frida by Davide Cioccia](https://1337.dcodx.com/mobile-security/owasp-mstg-crackme-2-writeup-android "Solution by Davide Cioccia")

<i style="color:gray">
By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller"). Special thanks to Michael Helwig for finding and fixing an oversight in the anti-tampering mechanism.
</i>

## Android UnCrackable L3

The crackme from hell! A secret string is hidden somewhere in this app. Find a way to extract it.

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk" class="mas-chip">Download</a>

??? info "Installation"
    This app is compatible with Android 4.4 and up.

    ```shell
    $ adb install UnCrackable-Level3.apk
    ```

??? danger "SPOILER (Solutions)"
    - [Solution using Frida by Eduardo Novella](https://enovella.github.io/android/reverse/2017/05/20/android-owasp-crackmes-level-3.html "Solution by Eduardo Novella").
    - [Solution using patches by sh3llc0d3r](https://web.archive.org/web/20210124164453/http://sh3llc0d3r.com/owasp-uncrackable-android-level3/ "Solution by sh3llc0d3r").
    - [Solution using Ghidra and Frida by Davide Cioccia](https://1337.dcodx.com/mobile-security/owasp-mstg-crackme-3-writeup-android "Solution by Davide Cioccia")

<i style="color:gray">
By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller").
Special thanks to [Eduardo Novella](https://github.com/enovella "Eduardo Novella") for testing, feedback and pointing out flaws in the initial build(s).
</i>

## Android UnCrackable L4

The Radare2 community always dreamed with its decentralized and free currency to allow r2 fans to make payments in places and transfer money between r2 users. A debug version of the r2Pay app has been developed and it will be supported very soon in many stores and websites. Can you verify that this is cryptographically unbreakable?

Hint: Run the APK in a non-tampered device to play a bit with the app.

1. There is a master PIN code that generates green tokens (aka r2coins) on the screen. If you see a red r2coin, then this token won't be validated by the community. You need to find out the 4 digits PIN code and the salt employed as well. Flag: `r2con{PIN_NUMERIC:SALT_LOWERCASE}`
2. There is a "r2pay master key" buried in layers of obfuscation and protections. Can you break the whitebox? Flag: `r2con{ascii(key)}`

**Versions:**

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_04/r2pay-v0.9.apk" class="mas-chip">Download v0.9</a>

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_04/r2pay-v1.0.apk" class="mas-chip">Download v1.0</a>

- `v0.9` - Release for OWASP MAS: Source code is available and the compilation has been softened in many ways to make the challenge easier and more enjoyable for newcomers.
- `v1.0` - Release for R2con CTF 2020: No source code is available and many extra protections are in place.

??? info "Installation"
    This app is compatible with Android 4.4 and up.

    ```shell
    $ adb install r2pay-v0.9.apk
    ```

??? danger "SPOILER (Solutions)"
    - [Solution bypassing protections using Frida/QBDI by Romain Thomas (v1.0)](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part1/ "Solution by Romain Thomas").
    - [Solution whitebox key recovery using SCAMarvels by Romain Thomas (v1.0)](https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part2/ "Solution by Romain Thomas").

<i style="color:gray">
Created and maintained by [Eduardo Novella](https://github.com/enovella "Eduardo Novella") & [Gautam Arvind](https://github.com/darvincisec "Gautam Arvind"). Special thanks to [NowSecure](https://www.nowsecure.com "NowSecure") for supporting this crackme.
</i>

## Android License Validator

A brand new Android app sparks your interest. Of course, you are planning to purchase a license for the app eventually, but you'd still appreciate a test run before shelling out $1. Unfortunately no keygen is available! Generate a valid serial key that is accepted by this app.

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/License_01/validate" class="mas-chip">Download</a>

??? info "Installation"
    Copy the binary to your Android device and run using the shell.

    ```shell
    $ adb push validate /data/local/tmp
    [100%] /data/local/tmp/validate
    $ adb shell chmod 755 /data/local/tmp/validate
    $ adb shell /data/local/tmp/validate
    Usage: ./validate <serial>
    $ adb shell /data/local/tmp/validate 1234
    Incorrect serial (wrong format).
    $ adb shell /data/local/tmp/validate JACE6ACIARNAAIIA
    Entering base32_decode
    Outlen = 10
    Entering check_license
    Product activation passed. Congratulations!
    ```

??? danger "SPOILER (Solutions)"
    - [Solution using symbolic execution by Bernhard Mueller](https://mas.owasp.org/MASTG/Android/0x05c-Reverse-Engineering-and-Tampering#symbolic-execution "Tampering and Reverse Engineering on Android - Symbolic Execution").

<i style="color:gray">
By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller")
</i>

## MASTG Hacking Playground

Did you enjoy working with the Crackmes? There is more! Go to [the MASTG Hacking Playground](https://github.com/OWASP/MASTG-Hacking-Playground "MASTG-playground") and find out!

<br><br>
