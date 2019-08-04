# Changelog

This document is automatically generated at {{gitbook.time}}

## v1.1.3 2 August 2019

- Updated Acknowledgments, with 2 new co-authors.
- Translated various parts into Japanese.
- A large restructuring of the general testing, platform specific testing and reverse-engineering chapters.
- Updated description of many tools: Adb, Angr, APK axtractor, Apkx, Burp Suite, Drozer, ClassDump(Z/etc), Clutch, Drozer, Frida, Hopper, Ghidra, IDB, Ipa Installer, iFunBox, iOS-deploy, KeychainDumper, Mobile-Security-Framework, Nathan, Needle, Objection, Magisk, PassionFruit, Radare 2, Tableplus, SOcket CAT, Xposed, and others.
- Updated most of the iOS hacking/verification techniques using iOS 12 or 11 as a base instead of iOS 9/10.
- Removed tools which were no longer updated, such as introspy-Android and AndBug.
- Added missing MASVS references from version 1.1.4: v1.X, V3.5, V5.6, V6.2-V6.5, V8.2-V8.6.
- Rewrote device-binding explanation and testcases for Android.
- Added parts on testing unmanaged code in Objective-C, Java, and C/C++.
- Applied many spelling, punctuation and style-related fixes.
- Updated many cryptography related parts.
- Added testaces for upgrade-mechanism verification for apps.
- Updated Readme, Code of Conduct, Contribution guidelines, verification, funding link, and generation scripts.
- Added ISBN as the book is now available at Hulu.
- Added various fixes for the .epub format.
- Added testcases on Android and iOS backup verification.
- Improved key-attestation related explanation for Android.
- Restructured OWASP Mobile Wiki.
- Removed Yahoo Weather app and simplified reference on using SQL injection.
- Improve explanation for iOS app sideloading to include various available methods.
- Added explanation on using ADB and device shell for Android.
- Added explanation on using device shell for iOS.
- Provided comparison for using emulators/simulators and real devices for iOS/Android.
- Fixed Uncrackable Level 3 for Android.
- Improved explanation on how to exfiltrate data and apps on iOS 12 and Android 8.
- Improved/updated explanation on SSL-pinning.
- Added list of adopters of the MASVS/MSTG.
- Updated English, Japanese, French and Spanish checklists to be compatible with MSTG 1.1.2.
- Added a small write-up on Adiantum for Google.
- Added MSTG-ID to the paragraphs to create a link between MSTG paragraphs and MASVS requirements.
- Added review criteria for Android instant apps and guidance for app-bundle evaluation.
- Clarified the differences between various methods of dynamic analysis.

## v1.1.2 12 May 2019

- Added missing mappings for MASVS V1.X.
- Updated markdown throughout the English MSTG to be consistent.
- Replaces some dead links.
- Improvements for rendering as a book, including the ISBN number.
- Updated the Excel: it is now available in Japanese as well!
- Many punctuation corrections, spelling and grammar issues resolved.
- Added missing iOS test case regarding memory corruption issues.
- Added contributing, code of conduct, markdown linting and dead link detection.

## v1.1.1 7 May 2019

- Improvements on various tool related parts, such as how to use on-device console, adb, nscurl, Frida and Needle.
- Updated 0x4e regarding SMS communication.
- Many grammar/style updates.
- Added Android description regarding MASVS requirement 7.8.
- Updated contributor list.
- Various updates on instructions regarding TLS and encryption.
- Removed some erroneous information.
- Fixed parts of the alignment of the MASVS requirements with the MSTG.
- Updated information on various topics such as jailbreaking and network interception on both iOS and Android.
- Added some steps for Frida detection.
- Added write-ups on Android changes, regarding permissions, application signing, device identifiers, key attestation and more.
- Extended guidance on SafetyNet attestation.
- Added information on Magisk.
- Added Firebase misconfiguration information.
- Added references to more testing tools.
- Updated contributor list.
- Added a lot of information to iOS platform testing.
- Added a lot of fixes for our book-release.

## v1.1.0 30 Nov 2018

- Added more samples in Kotlin.
- Simplified leanpub and gitbook publishing.
- A lot of QA improvements.
- Added deserialization test cases for iOS, including input sanitization.
- Added test cases regarding device-access-security policies and data storage on iOS.
- Added test cases regarding session invalidation.
- Improved cryptography and key management test cases on both Android and iOS.
- Started adding various updates in the test cases introduced by Android Oreo and Android Pie.
- Refreshed the Testing Tools section: removed some of the lesser maintained tools, added new tools.
- Fixed some of the markdown issues.
- Updated license to CC 4.0.
- Started Japanese translation.
- Updated references to OWASP Mobile Top 10.
- Updated Android Crackmes.
- Fixed some of the anti-reverse-engineering test cases.
- Added debugging test case for iOS.

## v1.0.2 13 Oct 2018

- Updated guiding documentation (README).
- Improved automated build of the pdf, epub and mobi.
- Updated Frontispiece (given new contributor stats).
- Added attack surface sections for Android and various.
- Added vulnerable apps for testing skills.
- Improved sections for testing App permissions for Android (given android Oreo/Pie), added section for testing permissions on iOS.
- Added fix for Fragment Injection on older Android versions.
- Improved sections on iOS WebView related testing.

## v1.0.1 17 Sept 2018

- Updated guiding documentation (README, PR templates, improved style guide, issue templates).
- Added automated build of the pdf and DocX.
- Updated Frontispiece (given new contributor stats).
- Updated Crackmes and guiding documentation.
- Updated tooling commands (adb, ABE, iMazing, Needle, IPAinstaller, etc.).
- Added first Russian translations of the 1.0 documents for iOS.
- Improved URLs for GitBook using goo.gl in case of URLs with odd syntax.
- Updated Frontispiece to give credit to all that have helped out for this version.
- Clarified the app taxonomy & security testing sections by a rewrite.
- Added sections for network testing, certificate verification & SSL pinning for Cordova, WebView, Xamarin, React-Native and updated the public key pinning sections.
- Removed no longer working guides (e.g. using iTunes to install apps).
- Updated a lot of URLs (using TLS wherever possible).
- Updated tests regarding WebViews.
- Added new testing tool suites in the tools section, such as the mobile hack tools and various dependency checkers.
- Updated test cases regarding protocol handlers (added missing MASVS 6.6 for iOS).
- Many small updates in terms of wording, spelling/typos, updated code segments and grammar.
- Added missing test cases for MASVS 2.11, 4.7, 7.5 and 4.11.
- Updated the XLS Checklist given MASVS 1.1.0.
- Removed the clipboard test from iOS and Android.
- Removed duplicates on local storage testing and updated data storage test cases.
- Added write-ups from the mobile security sessions at the OWASP summit.
- Added anti-debugging bypass section for iOS.
- Added SQL injection & XML injection samples and improved mitigation documentation.
- Added Needle documentation for iOS.
- Added fragment injection documentation.
- Updated IPA installation process guidance.
- Added XSS sample for Android.
- Added improved documentation for certificate installation on Android devices.
- Updated Frida & Fridump related documentation.
- Added sections about in-memory data analysis in iOS.
- Updated software development and related supporting documentation.
- Updated (anti) reverse-engineering sections for Android and iOS.
- Updated data storage chapters given newer tooling.
- Merged SDLC and security testing chapters.
- Updated cryptography and key-management testing sections for both Android and iOS (up to Android Nougat/iOS 11).
- Updated general overview chapters for Android and iOS.
- Updated Android and iOS IPC testing.
- Added missing overviews, references, etc. to various sections such as 0x6i.
- Updated local authentication chapters and the authentication & session management chapters.
- Updated test cases for sensitive data in memory.
- Added code quality sections.

## v1.0 15 Jun 2018 (First release)
