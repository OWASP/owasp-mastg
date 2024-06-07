# iOS Crackmes

## iOS UnCrackable L1

A secret string is hidden somewhere in this binary. Find a way to extract it. The app will give you a hint when started.

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/iOS/Level_01/UnCrackable-Level1.ipa" class="mas-chip">Download</a>

??? info "Installation"
    Open the "Device" window in Xcode and drag the IPA file into the list below "Installed Apps".

    Note: The IPA is signed with an Enterprise distribution certificate. You'll need to install the provisioning profile and trust the developer to run the app the "normal" way. Alternatively, re-sign the app with your own certificate, or run it on a jailbroken device (you'll want to do one of those anyway to crack it).

??? danger "SPOILER (Solutions)"
    - [Multiple solutions by David Weinstein](https://www.nowsecure.com/blog/2017/04/27/owasp-ios-crackme-tutorial-frida/ "Solutions by David Weinstein").
    - [Solution by Ryan Teoh](http://www.ryantzj.com/cracking-owasp-mstg-ios-crackme-the-uncrackable.html "Solution by Ryan Teoh").
    - [Solution with Angr by Vikas Gupta](https://serializethoughts.com/2019/10/28/solving-mstg-crackme-angr "Solving iOS UnCrackable 1 Crackme Without Using an iOS Device").
    - [Solution by Pietro Oliva](https://0xsysenter.github.io/ios/reversing/arm64/mobile/ipa/frida/instrumentation/crackme/2021/01/09/ios-apps-reverse-engineering-solving-crackmes-part-1.html "Solution by Pietro Oliva").

<i style="color:gray">
By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller")
</i>

## iOS UnCrackable L2

This app holds a secret inside - and this time it won't be tampered with!

Hint: it is related to alcoholic beverages.

<a href="https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/iOS/Level_02/UnCrackable-Level2.ipa" class="mas-chip">Download</a>

??? info "Installation"
    Open the "Device" window in Xcode and drag the IPA file into the list below "Installed Apps".
    
    Note 1: The IPA is signed with an Enterprise distribution certificate. You'll need to install the provisioning profile and trust the developer to run the app the "normal" way. Alternatively, re-sign the app with your own certificate, or run it on a jailbroken device (you'll want to do one of those anyway to crack it).
    
    Note 2: Due to its anti-tampering mechanisms the app won't run correctly if the main executable is modified and/or re-signed.

??? danger "SPOILER (Solutions)"
    - [Solution by Ryan Teoh](http://www.ryantzj.com/cracking-owasp-mstg-ios-crackme-the-uncrackable.html "Solution by Ryan Teoh").
    - [Solution by Pietro Oliva](https://0xsysenter.github.io/ios/reversing/arm64/mobile/ipa/frida/instrumentation/crackme/2021/02/08/ios-apps-reverse-engineering-solving-crackmes-part-2.html "Solution by Pietro Oliva").

<i style="color:gray">
By [Bernhard Mueller](https://github.com/muellerberndt "Bernhard Mueller")
</i>

<br><br>
