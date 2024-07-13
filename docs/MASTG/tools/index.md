# Testing Tools

The OWASP MASTG includes many tools to assist you in executing test cases, allowing you to perform static analysis, dynamic analysis, dynamic instrumentation, etc. These tools are meant to help you conduct your own assessments, rather than provide a conclusive result on an application's security status. It's essential to carefully review the tools' output, as it can contain both false positives and false negatives.

The goal of the MASTG is to be as accessible as possible. For this reason, we prioritize including tools that meet the following criteria:

- Open-source
- Free to use
- Capable of analyzing recent Android/iOS applications
- Regularly updated
- Strong community support

In instances where no suitable open-source alternative exists, we may include closed-source tools. However, any closed-source tools included must be free to use, as we aim to avoid featuring paid tools whenever possible. This also extends to freeware or community editions of commercial tools.

Our goal is to be vendor-neutral and to serve as a trusted learning resource, so the specific category of "automated mobile application security scanners" presents a unique challenge. For this reason, we have historically avoided including such tools due to the competitive disadvantages they can create among vendors. In contrast, we prioritize tools like MobSF that provide full access to their code and a comprehensive set of tests, making them excellent for educational purposes. Tools that lack this level of transparency, even if they offer a free version, generally do not meet the inclusion criteria of the OWASP MAS project.

> Disclaimer: Each tool included in the MASTG examples was verified to be functional at the time it was added. However, the tools may not work properly depending on the OS version of both your host computer and your test device. The functionality of the tools can also be affected by whether you're using a rooted or jailbroken device, the specific version of the rooting or jailbreaking method, and/or the tool version itself. The OWASP MASTG does not assume any responsibility for the operational status of these tools. If you encounter a broken tool or example, we recommend searching online for a solution or contacting the tool's provider directly. If the tool has a GitHub page, you may also open an issue there.

| ID                                                      | Name                             | Platform                                                                                                                                            |
|:--------------------------------------------------------|:---------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| #MASTG-TOOL-0080 | tcpdump                          | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0077 | Burp Suite                       | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0076 | bettercap                        | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0081 | Wireshark                        | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0079 | OWASP ZAP                        | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0078 | MITM Relay                       | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0075 | Android tcpdump                  | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0097 | mitmproxy                        | <span style="font-size: x-large; color: #9383e2;" title="Network"> :material-web: </span><span style="display: none;">platform:network</span>       |
| #MASTG-TOOL-0073     | radare2 for iOS                  | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0047     | Cydia                            | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0057     | lldb                             | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0063     | security                         | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0043     | class-dump                       | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0103     | IPSW                             | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0067     | swift-demangle                   | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0053     | iOSbackup                        | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0042     | BinaryCookieReader               | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0102     | ios-app-signer                   | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0066     | SSL Kill Switch 3                | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0072     | xcrun                            | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0046     | Cycript                          | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0056     | Keychain-Dumper                  | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0062     | Plutil                           | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0069     | Usbmuxd                          | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0049     | Frida-cycript                    | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0059     | optool                           | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0048     | dsdump                           | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0058     | MachoOView                       | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0068     | SwiftShield                      | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0039     | Frida for iOS                    | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0041     | nm - iOS                         | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0101     | codesign                         | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0065     | simctl                           | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0051     | gdb                              | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0071     | Xcode Command Line Tools         | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0045     | class-dump-dyld                  | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0055     | iProxy                           | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0061     | Grapefruit                       | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0070     | Xcode                            | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0044     | class-dump-z                     | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0054     | ios-deploy                       | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0060     | otool                            | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0040     | MobSF for iOS                    | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0074     | objection for iOS                | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0064     | Sileo                            | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0050     | Frida-ios-dump                   | <span style="font-size: x-large; color: #007aff;" title="iOS"> :material-apple: </span><span style="display: none;">platform:ios</span>             |
| #MASTG-TOOL-0022 | Proguard                         | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0016 | gplaycli                         | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0006 | Android SDK                      | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0012 | apkx                             | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0026 | Termux                           | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0002 | MobSF for Android                | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0013 | Busybox                          | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0027 | Xposed                           | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0003 | nm - Android                     | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0023 | RootCloak Plus                   | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0017 | House                            | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0007 | Android Studio                   | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0028 | radare2 for Android              | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0018 | jadx                             | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0008 | Android-SSL-TrustKiller          | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0019 | jdb                              | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0009 | APKiD                            | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0029 | objection for Android            | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0099 | FlowDroid                        | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0010 | APKLab                           | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0024 | Scrcpy                           | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0020 | JustTrustMe                      | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0014 | Bytecode Viewer                  | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0004 | adb                              | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0030 | Angr                             | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0021 | Magisk                           | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0015 | Drozer                           | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0005 | Android NDK                      | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0011 | Apktool                          | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0025 | SSLUnpinning                     | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0001 | Frida for Android                | <span style="font-size: x-large; color: #54b259;" title="Android"> :material-android: </span><span style="display: none;">platform:android</span>   |
| #MASTG-TOOL-0032 | Frida CodeShare                  | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0036 | r2frida                          | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0037 | RMS Runtime Mobile Security      | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0033 | Ghidra                           | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0038 | objection                        | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0098 | iaito                            | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0101 | disable-flutter-tls-verification | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0034 | LIEF                             | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0031 | Frida                            | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0100 | re-flutter                       | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |
| #MASTG-TOOL-0035 | MobSF                            | <span style="font-size: x-large; color: darkgrey;" title="Generic"> :material-asterisk: </span><span style="display: none;">platform:generic</span> |

<br>

