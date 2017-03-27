# Testing Processes and Techniques

## Mobile App Security Testing Methodology

-- TODO [Describe Mobile Security Testing methodology] --

### Testing Process

The following section will show how to use the OWASP mobile application security checklist and testing guide during a security test.

#### Preparation - Defining the baseline

First of all, you need to decide what security level of the MASVS to test against. The security requirements should ideally have been decided at the beginning of the SDLC - but unfortunately we're not living in an ideal world. At the very least, it is a good idea to walk through the checklist, ideally with an IT security representative of the enterprise and the app stakeholders of the project and make a reasonable selection of Level 2 (L2) controls to cover during the test.

The controls in MASVS Level 1 (L1) are appropriate for all mobile apps - the rest depends on the threat model and risk assessment for the particular app. Discuss with the app stakeholders what requirements are applicable and which ones are out of scope for testing, perhaps due to business decisions or company policies. Also consider whether some L2 requirements may be needed due to industry regulations or local laws - for example, 2-factor-authentation (2FA) may be obligatory for a financial app.

If security requirements were already defined during the SDLC, even better! Ask for this information and document it on the front page of the Excel sheet ("dashboard"). More guidance on the verification levels and guidance on the certification can be found in the [MASVS](https://github.com/OWASP/owasp-masvs).

![Preparation](Images/Chapters/0x03/mstg-preparation.png)

All involved parties need to agree on the decisions made and on the scope in the checklist, as this will present the baseline for all security testing, regardless if done manually or automatically.

#### Mobile App Security Testing

During a manual test you can simply walk through the applicable requirements one-by-one - for a detailed testing how-to simply click on the link in the "Test procedures" column. These links lead to the respective chapter in the OWASP Mobile Security Testing Guide. Note however that work on the guide is still ongoing so some test cases have not been written yet or might be in a draft status (ideally, if you discover missing content, you could contribute it yourself).

![The checklist. Requiremenets marked with "L1" should alwasy be verified. Choose either "Pass" or "Fail" in the "Status" column. The links in the "Testing Procedure" column lead to the OWASP Mobile Secuiryt Testing Guide.](Images/Chapters/0x03/mstg-test-cases.png)

The status column can have one of the following three different values, that need to be filled out:

* **Pass:** Requirement is applicable to mobile app and implemented according to best practices.
* **Fail:** Requirement is applicable to mobile app but not fulfilled.
* **N/A:** Requirement is not applicable to mobile app.

#### Reverse Engineering Resiliency Testing

*Resiliency Testing* is a new concept introduced in the OWASP MSTG. This kind of testing is used if the app implements defenses against client-side threats, such as tampering and extracting sensitive information. As we  know, such protection is never 100% effective. The goal in resiliency testing is to verify that no glaring weaknesses exist in the protection scheme, and that the expectations as to its effectiveness are met (e.g., a skilled reverse engineer should be forced to invest significant effort to do reach a particular goal).

#### The Management Summary

A spider chart is generated on the fly according to the results of the requirements for both supported platforms (Android and iOS) in the "Management Summary" tab. You can use this in your report to point out areas that need improvement, and visualize progress over time.

![Management Summary - Spider Chart](Images/Chapters/0x03/mstg-spiderchart.png)

The spider chart visualizes the ratio of passed and failed requirements in each domain. As can be seen above all requirements in "V3: Cryptography Verification Requirements" were set to "pass", resulting in a value of 1.00. Requirements that are set to N/A are not included in this chart.

A more detailed overview can also be found in the "Management Summary" tab. This table gives an overview according to the eight domains and breaks down the requirements according to it's status (Passed, Failed or N/A). The percentage column is the ratio from passed to failed requirements and is the input for the spider chart described above.

![Management Summary - Detailed Overview](Images/Chapters/0x03/mstg-detailed-summary.png)

#### Risk Assessment

#### Reporting

## Vulnerability Analysis Techniques

### Static Analysis

-- TODO [Describe Static Analysis techniques in Mobile Testing in a general manner] --

#### Automatic Code Analysis

-- TODO [Describe Automatic code analysis : goal, how it works, pros / cons, role in pentests] --

#### Manual Code Review

-- TODO [Describe Manual Code Review : goal, how it adds to automatic code analysis, how it works, pros / cons, kind of issues that can be found only manually] --

### Dynamic Analysis

#### Runtime Analysis

-- TODO [Describe Runtime Analysis : goal, how it works, kind of issues that can be found] --

#### Traffic Analysis

Dynamic analysis of the traffic exchanged between client and server can be performed by launching a Man-in-the-middle (MITM) attack. This can be achieved by using an interception proxy like Burp Suite or OWASP ZAP for HTTP traffic.  

* [Configuring an Android Device to work with Burp](https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp)
* [Configuring an iOS Device to work with Burp](https://support.portswigger.net/customer/portal/articles/1841108-configuring-an-ios-device-to-work-with-burp)

In case another (proprietary) protocol is used in a mobile App that is not HTTP, the following tools can be used to try to intercept or analyze the traffic:
* [Mallory](https://github.com/intrepidusgroup/mallory)
* [Wireshark](https://www.wireshark.org/)

#### Input Fuzzing
Fuzz testing, is a method for testing software input validation by feeding it intentionally malformed input.
Steps in fuzzing
* Identifying a target
* Generating malicious inputs
* Test case delivery
* Crash monitoring

[OWASP Fuzzing guide](https://www.owasp.org/index.php/Fuzzing)

Note: Fuzzing only detects software bugs. Classifying this issue as a security flaw requires further analysis by the researcher.

## Tampering and Reverse Engineering

Reverse engineering and tampering techniques have long belonged to the realm of crackers, modders, malware analysts, and other more exotic professions. For "traditional" security testers and researchers, reverse engineering has been more of a complementary, nice-to-have-type skill that wasn't all that useful in 99% of day-to-day work. But the tides are turning: Mobile app black-box testing increasingly requires testers to disassemble compiled apps, apply patches, and tamper with binary code or even live processes. The fact that many mobile apps implement defenses against unwelcome tampering doesn't make things easier for us.

Mobile security testers should be able to understand basic reverse engineering concepts. It goes without saying that they should also know mobile devices and operating systems inside out: The processor architecture, executable format, programming language intricacies, and so forth.

Reverse engineering is an art, and describing every available facet of it would fill a whole library. The sheer range of techniques and possible specializations is mind-blowing: One can spend years working on a very specific, isolated sub-problem, such as automating malware analysis or developing novel de-obfuscation methods. Security testers are generalists: To be effective reverse engineers, they must be able filter through the vast amount of information to build a workable methodology.

There is no generic reverse engineering process that always works. That said, we'll describe commonly used methods and tools later on, and give examples for tackling the most common defenses.

### Why You Need It

Mobile security testing requires at least basic reverse engineering skills for several reasons:

**1. To enable black-box testing of mobile apps.** Modern apps often employ technical controls that will hinder your ability to perform dynamic analysis. SSL pinning and end-to-end (E2E) encryption sometimes prevent you from intercepting or manipulating traffic with a proxy. Root detection could prevent the app from running on a rooted device, preventing you from using advanced testing tools. In this cases, you must be able to deactivate these defenses.

**2. To enhance static analysis in black-box security testing.** In a black-box test, static analysis of the app bytecode or binary code is helpful for getting a better understanding of what the app is doing. It also enables you to identify certain flaws, such as credentials hardcoded inside the app.

**3. To assess resiliency against reverse engineering.**  Apps that implement the software protection measures listed in MASVS-R should be resilient against reverse engineering to a certain degree. In this case, testing the reverse engineering defenses ("resiliency assessment") is part of the overall security test. In the resiliency assessment, the tester assumes the role of the reverse engineer and attempts to bypass the defenses.

In this guide, we'll cover basic tampering techniques such as patching and hooking, as well as common tools and processes for reverse engineering (and comprehending) mobile apps without access to the original source code. Reverse engineering is an immensely complex topic however - covering every possible aspect would easily fill several books. Links and pointers to useful resources are included in the "references" section at the end of each chapter.

### Before You Start

Before you dive into the world of mobile app reversing, we have some good news and some bad news for you. Let's start with the good news:

**Ultimately, the reverse engineer always wins.**

This is even more true in the mobile world, where the reverse engineer has a natural advantage: The way mobile apps are deployed and sandboxed is more restrictive by design, so it is simply not feasible to include the rootkit-like functionality like it is often found in Windows software (e.g. DRM systems). At least on Android, you have a much higher degree of control over the mobile OS, giving you easy wins in many situations (assuming you know how to use that power). On iOS, you get less control - but defensive options are even more limited.

On the other hand, dealing with multi-threaded anti-debugging controls, cryptographic white-boxes, stealthy anti-tampering features and highly complex control flow transformations is not for the faint-hearted.  By nature, the best software protection schemes are highly proprietary, and while many tasks can be automated, the way to successful reversing is plastered with good amounts of thinking, coding, frustration, and - depending on your personality - sleepless nights and strained relationships.

It's easy to get overwhelmed by the sheer scope of it in the beginning. The best way to get started is to set up some basic tools (see the respective sections in the Android and iOS reversing chapters) and starting doing simple reversing tasks and crackmes. As you go, you'll need to learn about the assembler/bytecode language, the operating system in question, obfuscations you encounter, and so on. Start with simple tasks and gradually level up to more difficult ones.

### Basic Tampering Techniques

Tampering is the process of making changes to a mobile app (either the compiled app, or the running process) or its environment to affect its behavior. For example, an app might refuse to run on your rooted test device, making it impossible to run some of your tests. In cases like that, you'll want to alter that particular behavior.

In the following section we'll give a high level overview of the techniques most commonly used in mobile app security testing. Later, we'll drill down into OS-specific details for both Android and iOS.

#### Binary Patching

Patching means making changes to the compiled app - e.g. changing code in a binary executable file(s), modifying Java bytecode, or tampering with resources. Patches can be applied in any number of ways, from decompiling, editing and re-assembling an app, to editing binary files in a hex editor - anything goes (this rule applies to all of reverse engineering). We'll give some detailed examples for useful patches in later chapters.

One thing to keep in mind is that modern mobile OSes strictly enforce code signing, so running modified apps is not as straightforward as it used to be in traditional Desktop environments. Yep, security experts had a much easier life in the 90s! Fortunately, this is not all that difficult to do if you work on your own device - it simply means that you need to re-sign the app, or disable the default code signature verification facilities to run modified code.

#### Runtime Tampering

Code injection is a very powerful technique that allows you to explore and modify processes during runtime. The injection process can be implemented in various ways, but you'll get by without knowing all the details thanks to freely available, well-documented tools that automate it. These tools give you direct access to process memory and important structures such as live objects instantiated by the app, and come with many useful utility functions for resolving loaded libraries, hooking methods and native functions, and more. Tampering with process memory is more difficult to detect than patching files, making in the preferred method in the majority of cases.

Substrate, Frida and XPosed are the most widely used hooking & code injection frameworks in the mobile reversing world. The three frameworks differ in design philosophy and implementation details: Substrate and Xposed focus on code injection and/or hooking, while Frida aims to be a full-blown "dynamic instrumentation framework" that incorporates both code injection and language bindings, as well as an injectable JavaScript VM and console. However, you can also instrument apps with Substrate by using it to inject Cycript, the programming environment (a.k.a. "Cycript-to-JavaScript" compiler) authored by Saurik of Cydia fame. To complicate things even more, Frida's authors also created a fork of Cycript named ["frida-cycript"](https://github.com/nowsecure/frida-cycript) that replaces Cycript's runtime with a Frida-based runtime called Mjølner. This enables Cycript to run on all the platforms and architectures maintained by frida-core (if you are confused now don't worry, it's perfectly OK to be). The release was accompanied by a blog post by Frida's developer Ole titled "Cycript on Steroids", which [did not go that down that well with Saurik](https://www.reddit.com/r/ReverseEngineering/comments/50uweq/cycript_on_steroids_pumping_up_portability_and/).

We'll include some examples for all three frameworks. For your first pick, it's probably best to start with Frida, as it is the most versatile of the three (for this reason we'll also include a bit more details on Frida). Notably, Frida can inject a Javascript VM into a process on both Android and iOS, while Cycript injection with Substrate only works on iOS. Ultimately however, you can achieve many of the same end goals with either framework.

### Static and Dynamic Binary Analysis

Reverse engineering is the process of reconstructing the semantics of the original source code from a compiled program. In other words, you take the program apart, run it, simulate parts of it, and do other unspeakable things to it, in order to understand what exactly it is doing and how.

#### Using Disassemblers and Decompilers

Disassemblers and decompilers allow you to translate an app binary code or byte-code back into a more or less understandable format. In the case of native binaries, you'll usually obtain assembler code matching the architecture which the app was compiled for. Android Java apps can be disassembled to Smali (an Assembler language for the dex format), and also quite easily decompiled back to Java code.

A wide range of tools and frameworks is available: From expensive, but convenient GUI tools, to open source disassembling engines and reverse engineering frameworks. Advanced usage instructions for any of these tools often easily fill a book on their own. We'll introduce some of the most widely used disassemblers in the following section. The best way to get started is simply pick the tool that fits your needs and budget and buy a well-reviewed user guide along with it (some recommendations are listed below).

-- TODO [Introduce a few standard tools, IDA Pro, Hopper, Radare2, JEB (?)] --

-- TODO [Talk about IDA Scripting and the many plugins developed by the community] --

#### Debugging

-- TODO [Describe Debugging : how it works, when you can / have to use it, examples of tools] --

#### Execution Tracing

-- TODO [Describe Execution Tracing : how it works, when you can / have to use it, examples of tools] --

### Advanced Techniques

For more complicated tasks, such as de-obfuscating heavily obfuscated binaries, you won't get far without automating certain parts of the analysis. For example, understanding and simplifying a complex control flow graph manually in the disassembler would take you years (and most likely drive you mad, way before you're done). Instead, you can augment your workflow with custom made scripts or tools. Fortunately, modern disassemblers come with scripting and extension APIs, and many useful extensions are available for popular ones. Additionally, open-source disassembling engines and binary analysis frameworks exist to make your life easier.

Like always in hacking, the anything-goes-rule applies: Simply use whatever brings you closer to your goal most efficiently. Every binary is different, and every reverse engineer has their own style. Often, the best way to get to the goal is to combine different approaches, such as emulator-based tracing and symbolic execution, to fit the task at hand. To get started, pick a good disassembler and/or reverse engineering framework and start using them to get comfortable with their particular features and extension APIs. Ultimately, the best way to get better is getting hands-on experience.

-- TODO [Develop on Advanced Techniques] --

#### Dynamic Binary Instrumentation

Another useful method for dealing with native binaries is dynamic binary instrumentations (DBI). Instrumentation frameworks such as Valgrind and PIN support fine-grained instruction-level tracing of single processes. This is achieved by inserting dynamically generated code at runtime. Valgrind compiles fine on Android, and pre-built binaries are available for download. The [Valgrind README](http://valgrind.org/docs/manual/dist.readme-android.html) contains specific compilation instructions for Android.

#### Emulation-based Dynamic Analysis

Running an app in the emulator gives you powerful ways to monitor and manipulate its environment. For some reverse engineering tasks, especially those that require low-level instruction tracing, emulation is the best (or only) choice.

-- TODO [Develop on Emulation-based Dynamic Analysis] --

#### Program Analysis Using Symbolic / Concolic Execution

-- TODO [Introduce RE frameworks] --

In the late 2000s, symbolic-execution based testing has gained popularity as a means of identifying security vulnerabilities. Symbolic "execution" actually refers to the process of representing possible paths through a program as formulas in first-order logic, whereby variables are represented by symbolic values, which are actually entire ranges of values. Satisfiability Modulo Theories (SMT) solvers are used to check satisfiability of those formulas and provide a solution, including concrete values for the variables needed to reach a certain point of execution on the path corresponding to the solved formula.

Typically, this approach is used in combination with other techniques such as dynamic execution (hence the name concolic stems from *conc*rete and symb*olic*), in order to tone down the path explosion problem specific to classical symbolic execution. This together with improved SMT solvers and current hardware speeds, allow concolic execution to explore paths in medium size software modules (i.e. in the order of 10s KLOC). However, it also comes in handy for supporting de-obfuscation tasks, such as simplifying control flow graphs. For example, Jonathan Salwan and Romain Thomas have shown how to reverse engineer VM-based software protections using Dynamic Symbolic Execution (i.e., using a mix of actual execution traces, simulation and symbolic execution) [1].

In the Android section, you'll find a walkthrough for cracking a simple license check in an Android application using symbolic execution.

#### Domain-Specific De-Obfuscation Attacks

## Additional Considerations

### Eliminating False Positives

#### Cross-Site Scripting (XSS)

A typical reflected XSS attack is executed by sending a URL to the victim(s), which for example can contain a payload to connect to some exploitation framework like BeeF [2]. When clicking on it a reverse tunnel is established with the Beef server in order to attack the victim(s). As a WebView is only a slim browser it is not possible for a user to insert a URL into a WebView of an App as no adress bar is available. Also clicking on a link will not open the URL in a WebView of an App, instead it will open directly within the browser of Android. Therefore a typical reflected Cross-Site Scripting attack that targets a WebView in an App is not applicable and will not work.

If an attacker finds a stored Cross-Site Scripting vulnerability in an endpoint, or manages to get a Man-in-the-middle (MITM) position and injects JavaScript into the response, then the exploit will be sent back within the response. The attack will then be executed directly within the WebView. This can become dangerous in case:

* JavaScript is not deactivated in the WebView (see OMTG-ENV-005)
* File access is not deactivated in the WebView (see OMTG-ENV-006)
* The function addJavascriptInterface() is used (see OMTG-ENV-008)

As a summary reflected XSS is no concern for a mobile App, but stored XSS or injected JavaScript through MITM can become a dangerous vulnerability if the WebView in use is configured insecurely.

#### Cross-Site Request Forgery (CSRF)

The same problem described with reflected XSS also applied to CSRF attacks. A typical CSRF attack is executed by sending a URL to the victim(s) that contains a state changing request like creation of a user account of triggering a financial transaction. As a WebView is only a slim browser it is not possible for a user to insert a URL into a WebView of an App and also clicking on a link will not open the URL in a WebView of an App. Instead it will open directly within the browser of Android. Therefore a typical CSRF attack that targets a WebView in an App is not applicable.

The basis for CSRF attacks, access to session cookies of all browser tabs and attaching them automatically if a request to a web page is executed is not applicable on mobile platforms. This is the default behaviour of full blown browsers. Every App has, due to the sandboxing mechanism, it's own web cache and stores it's own cookies, if WebViews are used. Therefore a CSRF attack against a mobile App is by design not possible as the session cookies are not shared with the Android browser.

Only if a user logs in by using the Android browser (instead of using the mobile App) a CSRF attack would be possible, as then the session cookies are accessible for the browser instance.

### References

- [1] https://triton.quarkslab.com/files/csaw2016-sos-rthomas-jsalwan.pdf
- [2] OWASP Mobile Application Security Verification Standard - https://www.owasp.org/images/f/f2/OWASP_Mobile_AppSec_Verification_Standard_v0.9.2.pdf
- Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- Another Informational Article - http://www.securityfans.com/informational_article.html



