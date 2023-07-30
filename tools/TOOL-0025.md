---
title: Drozer
platform: android
refs:
  - https://github.com/FSecureLABS/drozer
---

[Drozer](https://github.com/FSecureLABS/drozer "Drozer on GitHub") is an Android security assessment framework that allows you to search for security vulnerabilities in apps and devices by assuming the role of a third-party app interacting with the other application's IPC endpoints and the underlying OS.

The advantage of using drozer consists on its ability to automate several tasks and that it can be expanded through modules. The modules are very helpful and they cover different categories including a scanner category that allows you to scan for known defects with a simple command such as the module `scanner.provider.injection` which detects SQL injections in content providers in all the apps installed in the system. Without drozer, simple tasks such as listing the app's permissions require several steps that include decompiling the APK and manually analyzing the results.

#### Installing Drozer

You can refer to [drozer GitHub page](https://github.com/FSecureLABS/drozer "Drozer on GitHub") (for Linux and Windows, for macOS please refer to this [blog post](https://fi5t.xyz/en/posts/drozer-on-mac/ "(not)Unique experience blog - Installing Drozer on macOS Catalina")) and the [drozer website](https://labs.withsecure.com/tools/drozer/ "Drozer Website") for prerequisites and installation instructions.

#### Using Drozer

Before you can start using drozer, you'll also need the drozer agent that runs on the Android device itself. Download the latest drozer agent [from the GitHub releases page](https://github.com/FSecureLABS/drozer/releases/ "drozer GitHub releases") and install it with `adb install drozer.apk`.

Once the setup is completed you can start a session to an emulator or a device connected per USB by running `adb forward tcp:31415 tcp:31415` and `drozer console connect`. This is called direct mode and you can see the full instructions in the [User Guide in section "Starting a Session"](https://labs.withsecure.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf "Starting a Session"). An alternative is to run Drozer in infrastructure mode, where, you are running a drozer server that can handle multiple consoles and agents, and routes sessions between them. You can find the details of how to setup drozer in this mode in the ["Infrastructure Mode"](https://labs.withsecure.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf "Infrastructure Mode") section of the User Guide.

Now you are ready to begin analyzing apps. A good first step is to enumerate the attack surface of an app which can be done easily with the following command:

```bash
dz> run app.package.attacksurface <package>
```

Again, without drozer this would have required several steps. The module `app.package.attacksurface` lists activities, broadcast receivers, content providers and services that are exported, hence, they are public and can be accessed through other apps. Once we have identified our attack surface, we can interact with the IPC endpoints through drozer without having to write a separate standalone app as it would be required for certain tasks such as communicating with a content provider.

For example, if the app has an exported Activity that leaks sensitive information we can invoke it with the Drozer module `app.activity.start`:

```bash
dz> run app.activity.start --component <package> <component name>
```

This previous command will start the activity, hopefully leaking some sensitive information. Drozer has modules for every type of IPC mechanism. Download [InsecureBankv2](0x08b-Reference-Apps.md#insecurebankv2) if you would like to try the modules with an intentionally vulnerable application that illustrates common problems related to IPC endpoints. Pay close attention to the modules in the scanner category as they are very helpful automatically detecting vulnerabilities even in system packages, specially if you are using a ROM provided by your cellphone company. Even [SQL injection vulnerabilities in system packages by Google](https://issuetracker.google.com/u/0/issues/36965126 "SQL injection in Android") have been identified in the past with drozer.

#### Other Drozer commands

Here's a non-exhaustive list of commands you can use to start exploring on Android:

```bash
# List all the installed packages
$ dz> run app.package.list

# Find the package name of a specific app
$ dz> run app.package.list -f (string to be searched)

# See basic information
$ dz> run app.package.info -a (package name)

# Identify the exported application components
$ dz> run app.package.attacksurface (package name)

# Identify the list of exported Activities
$ dz> run app.activity.info -a (package name)

# Launch the exported Activities
$ dz> run app.activity.start --component (package name) (component name)

# Identify the list of exported Broadcast receivers
$ dz> run app.broadcast.info -a (package name)

# Send a message to a Broadcast receiver
$ dz> run app.broadcast.send --action (broadcast receiver name) -- extra (number of arguments)

# Detect SQL injections in content providers
$ dz> run scanner.provider.injection -a (package name)
```

#### Other Drozer resources

Other resources where you might find useful information are:

- [Official drozer User Guide](https://labs.withsecure.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf "Drozer User Guide").
- [drozer GitHub page](https://github.com/FSecureLABS/drozer "GitHub repo")
- [drozer Wiki](https://github.com/FSecureLABS/drozer/wiki "drozer Wiki")