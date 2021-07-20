## v1.2 - 21 July 2021

167 issues were closed since the last release. A full overview can be seen in Github Issues <https://github.com/OWASP/owasp-mstg/issues?q=is%3Aissue+is%3Aclosed+closed%3A2019-08-03..2021-07-21>.

325 pull requests were merged since the last release. A full overview can be seen in Github Pull Requests <https://github.com/OWASP/owasp-mstg/pulls?q=is%3Apr+is%3Aclosed+closed%3A2019-08-03..2021-07-21>

Major changes include:

- Migrating the new document build pipeline from MASVS to MSTG. This allows us to build consistently the whole OWASP MSTG documents (PDF, docx etc.) in minutes, without any manual work.
- Besides numerous changes for the test cases we have a new Crackme - Android Level 4 <https://github.com/OWASP/owasp-mstg/tree/master/Crackmes/Android/Level_04> and also new write-ups for the Crackmes.
- We removed all references to Needle and IDB tool, as both tools are outdated.
- References of OWASP Mobile Top 10 and MSTG-IDs are completely moved to MASVS
- Reworking of information gathering (static analysis) for Android Apps
- Update of Biometric Authentication for Android Apps
- New content and updates in the Android and iOS Reverse Engineering and Tampering chapters
- 3 new iOS Reverse Engineering test cases
- Translations of the MSTG are linked to the respective forks but are not part of the MSTG anymore
- Updated English, Japanese, French, Korean and Spanish checklists to be compatible with MSTG 1.2
- Updated Acknowledgments, with 1 new co-author and contributor
- Added JNI Tracing for Android
- Added dsdump for dumping Objective-C and Swift content
- Added the procedure to sign the debugserver for iOS 12 and higher
- Added dependency-check to verify for vulnerabilities in libraries added by iOS package managers
- Added getppid as debugger detection (iOS)
- Added Domain/URL Enumeration in APKs
- Added introduction into Network.framework (iOS)
- Added UnSAFE Bank iOS Application
- Added information on SECCOMP (Android)
- Added native and java method tracing (Android)
- Added Android library injection
- Added Android 10 TLS and cryptography updates
- Updated code obfuscation for Android and iOS
- Added test case for Reverse Engineering Tools Detection - MSTG-RESILIENCE-4 (iOS)
- Added test case for Emulator Detection - MSTG-RESILIENCE-5 (iOS)
- Added an example with truststore to bypass cert pinning (Android)
- Added content to information gathering using frida (Android)
- Added RandoriSec and OWASP Bay area as sponsor
- Added basic information gathering for Android and iOS
- Added Simulating a Man-in-the-Middle Attack with an Access Point
- Added gender neutrality to the MSTG
- Extended section about dealing with Xamarin Apps
- Updated all picture links to img tag
- Updated iTunes limitations and usage since macOS Catalina
- Added Emulation-based Analysis (iOS and Android)
- Added Debugging iOS release applications using lldb
- Added Korean translation of the checklist
- Updated symbolic execution content (Android)
- Added Ghidra for Android Reverse Engineering
- Added section on Manual (Reversed) Code Review for iOS
- Added explanation of more Frida APIs (iOS and Android)
- Added Apple CryptoKit
- Updated and simplified Frida detection methods
- Added introduction to setup and disassembling for iOS Apps
- Updated section about frida-ios-dump
- Added gplaycli (Android)
- Extended section on how to retrieve UDI (iOS)
- Added new companies in the Users.md list with companies applying the MSTG/MASVS
- Updated code samples to Swift 5
- Adding Process Exploration (Android and iOS)
- Updated best practices for passwords, added "Have I Been Pwned"
- Updated SSL Pinning fallback methods
- Updated app identifier (Android and iOS)
- Updated permission changes for Android O, P and Q
- Updated Broadcast Receiver section (Android)

Several other minor updates include fixing typos and markdown lint errors and updating outdated links.

We thank you all contributors for the hard work and continuously improving the document and the OWASP MSTG project!
