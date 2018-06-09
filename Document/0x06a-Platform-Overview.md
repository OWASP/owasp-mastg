## iOS Platform Overview

iOS is a mobile operating system that powers Apple mobile devices, including the iPhone, iPad, and iPod Touch. It is also the basis for Apple tvOS, which inherits many functionalities from iOS.

Like the Apple desktop operating system macOS (formerly OS X), iOS is based on Darwin, an open source Unix operating system developed by Apple. Darwin's  kernel is XNU ("X is Not Unix"), a hybrid kernel that combines components of the Mach and FreeBSD kernels.

However, iOS apps run in a more restricted environment than their desktop counterparts do. iOS apps are isolated from each other at the file system level and are significantly limited in terms of system API access.

To protect users from malicious applications, Apple restricts and controls access to the apps that are allowed to run on iOS devices. The Apple App store is the only official application distribution platform. There developers can offer their apps and consumers can buy, download, and install apps. This distribution style differs from Android, which supports several app stores and sideloading (installing an app on your iOS device without using the official App store).

In the past, sideloading was  possible only with a jailbreak or complicated workarounds. With iOS 9 or higher, it is possible to [sideload via Xcode](https://www.igeeksblog.com/how-to-sideload-apps-on-iphone-ipad-in-ios-10/ "How to Sideload Apps on iPhone and iPad Running iOS 10 using Xcode 8").

iOS apps are isolated from each other via the Apple sandbox (historically called Seatbelt),s a mandatory access control (MAC) mechanisms describing the resources an app can and can't access. Compared to Android's extensive Binder IPC facilities, iOS offers very few IPC options, minimizing the potential attack surface.

Uniform hardware and tight hardware/software integration create another security advantage. Every iOS device offers security features, such as secure boot, hardware-backed keychain, and file system encryption. iOS updates are usually quickly rolled out to a large percentage of users, decreasing the need to support older, unprotected iOS versions.

In spite of the numerous strengths of iOS, iOS app developers still need to worry about security. Data protection, Keychain, TouchID authentication, and network security still leave a large margin for errors. In the following chapters, we describe iOS security architecture, explain a basic security testing methodology, and provide reverse engineering how-tos.


### iOS Security Architecture

The [iOS security architecture](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "Apple iOS Security Guide") consists of six core features:

- Hardware Security
- Secure Boot
- Code Signing
- Sandbox
- Encryption and Data Protection
- General Exploit Mitigations

![iOS Security Architecture](Images/Chapters/0x06a/iOS_Security_Architecture.png)


#### Hardware Security

The iOS security architecture makes good use of hardware-based security features that enhance overall performance. Each iOS device comes with two built-in Advanced Encryption Standard (AES) 256-bit keys – GID and UID – that are fused and compiled into the application processor and Secure Enclave during manufacturing. There's no direct way to read these keys with software or debugging interfaces such as JTAG. Encryption and decryption operations are performed by hardware AES crypto-engines that have exclusive access to these keys.

The GID is a value shared by all processors in a class of devices used to prevent tampering with firmware files and other cryptographic tasks not directly related to the user's private data. UIDs, which are unique to each device, are used to protect the key hierarchy that's used for device-level file system encryption. Because UIDs aren't recorded during manufacturing, not even Apple can restore the file encryption keys for a particular device.

To allow secure deletion of sensitive data on flash memory, iOS devices include a feature called [Effaceable Storage](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide"). This feature provides direct low-level access to the storage technology, making it possible to securely erase selected blocks.

#### Secure Boot

When an iOS device is powered on, it reads the initial instructions from the read-only Boot ROM, which bootstraps the system. The Boot ROM contains immutable code and the Apple Root CA, which is etched into the silicon die during the fabrication process, thereby creating the root of trust. Next, the Boot ROM makes sure that the iBoot bootloader's signature is correct. After the signature is validated, the iBoot checks the signature of the next boot stage, which is the iOS kernel. If any of these steps fail, the boot process will terminate immediately and the device will enter recovery mode and display the "Connect to iTunes" screen. However, if the Boot ROM fails to load, the device will enter a special low-level recovery mode called Device Firmware Upgrade (DFU). This is the last resort for restoring the device to its original state. In this mode, the device will show no sign of activity; i.e., its screen won't display anything.

This entire process is called the "Secure Boot Chain". Its purpose is ensuring that the system and its components are written and distributed by Apple. The Secure Boot chain consists of the kernel, the bootloader, the kernel extension, and the baseband firmware.

#### Code Signing

Apple has implemented an elaborate DRM system to make sure that only Apple-approved code runs on their devices. In other words, you won't be able to run any code on an iOS device that hasn't been jailbroken unless Apple explicitly allows it. End users are supposed to install apps through the official Apple app store only. For this reason (and others), iOS has been [compared to a crystal prison](https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms "Apple's Crystal Prison and the Future of Open Platforms").

A developer profile and an Apple-signed certificate are required to deploy and run an application.
Developers need to register with Apple, join the [Apple Developer Program](https://developer.apple.com/support/compare-memberships/ "Membership for Apple Developer Program") and pay a yearly subscription to get the full range of development and deployment possibilities. There's also a free account that allows you to compile and deploy apps (but not distribute them in the App Store) via sideloading.

#### Encryption and Data Protection

*FairPlay Code Encryption* is applied to apps downloaded from the App Store. FairPlay was developed as a DRM for multimedia content purchased through iTunes. Originally, Fairplay encryption was applied to MPEG and QuickTime streams, but the same basic concepts can also be applied to executable files. The basic idea is as follows: Once you register a new Apple user account, a public/private key pair will be created and assigned to your account. The private key is securely stored on your device. This means that FairPlay-encrypted code can be decrypted only on devices associated with your account. Reverse FairPlay encryption is usually obtained by running the app on the device, then dumping the decrypted code from memory (see also "Basic Security Testing on iOS").

Apple has built encryption into the hardware and firmware of its iOS devices since the release of the iPhone 3GS. Every device has a dedicated hardware-based crypto engine that's based on the 256-bit AES, which works with a SHA-1 cryptographic hash function. In addition, there's a unique identifier (UID) built into each device's hardware with an AES 256-bit key fused into the application processor. This UID is unique and not recorded elsewhere. At the time of writing, neither software nor firmware can directly read the UID. Because the key is burned into the silicon chip, it can't be tampered with or bypassed. Only the crypto engine can access it.

Building encryption into the physical architecture makes it a default security feature that can encrypt all data stored on an iOS device. As a result, data protection is implemented at the software level and works with the hardware and firmware encryption to provide more security.

When data protection is enabled, each data file is associated with a specific class. Each class supports a different level of accessibility and protects data on the basis of when the data needs to be accessed. The encryption and decryption operations associated with each class are based on multiple key mechanisms that utilize the device's UID and passcode, a class key, a file system key, and a per-file key. The per-file key is used to encrypt the file's contents. The class key is wrapped around the per-file key and stored in the file's metadata. The file system key is used to encrypt the metadata. The UID and passcode protect the class key. This operation is invisible to users. To enable data protection, the passcode must be used when accessing the device. The passcode unlocks the device. Combined with the UID, the passcode also creates iOS encryption keys that are more resistant to hacking and brute-force attacks. Enabling data protection is the main reason for users to use passcodes on their devices.

#### Sandbox

The [appsandbox](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html "File System Basics") is an iOS access control technology. It is enforced at the kernel level. Its purpose is limiting system and user data damage that may occur when an app is compromised.

Sandboxing has been a core security feature since the first release of iOS. All third-party apps run under the same user (`mobile`), and only a few system applications and services run as `root`. Regular iOS apps are confined to a *container* that restricts access to the app's own files and a very limited number of system APIs. Access to all resources (such as files, network sockets, IPCs, and shared memory) are controlled by the sandbox. These restrictions work as follows [#levin]:

- The app process is restricted to its own directory (under /var/mobile/Containers/Bundle/Application/) via a chroot-like process.
- The `mmap` and `mmprotect` system calls are modified to prevent apps from making writeable memory pages executable and stopping processes from executing dynamically generated code. In combination with code signing and FairPlay, this strictly limits what code can run under specific circumstances (e.g., all code in apps distributed via the app store is approved by Apple).
-  Processes are isolated from each other, even if they are owned by the same UID.
- Hardware drivers can't be accessed directly. Instead, they must be accessed through Apple's frameworks.

#### General Exploit Mitigations

iOS implements address space layout randomization (ASLR) and eXecute Never (XN) bit to mitigate code execution attacks.

ASLR randomizes the memory location of the program's executable file, data, heap, and stack every time the program is executed. Because the shared libraries must be static to be accessed by multiple processes, the addresses of shared libraries are randomized every time the OS boots instead of every time the program is invoked. This makes specific function and library memory addresses hard to predict, thereby preventing attacks such as the return-to-libc attack, which involves the memory addresses of basic libc functions.

The XN mechanism allows iOS to mark selected memory segments of a process as non-executable. On iOS, the process stack and heap of user-mode processes is marked non-executable. Pages that are writable cannot me marked executable at the same time. This prevent attackers to execute machine code injected into the stack or heap.

### Software Development on iOS

Like other platforms, Apple provides a Software Development Kit (SDK) that helps developers to develop, install, run, and test native iOS Apps. Xcode is an Integrated Development Environment (IDE) for Apple development. iOS applications are developed in Objective-C or Swift.

Objective-C is an object-oriented programming language that adds Smalltalk-style messaging to the C programming language. It is used on macOS to develop desktop applications and on iOS to develop mobile applications. Swift is the successor of Objective-C and allows interoperability with Objective-C.

Swift was introduced with Xcode 6 in 2014.

On a non-jailbroken device, there are two ways to install an application without the App Store:

1. via Enterprise Mobile Device Management. This requires a company-wide certificate signed by Apple.
2. via sideloading, i.e., by signing an app with a developer's certificate and installing it on the device via Xcode. A limited number of devices can be installed to with the same certificate.

### Apps on iOS

iOS apps are distributed in IPA (iOS App Store Package) archives. The IPA file is a ZIP-compressed archive that contains all the code and resources required to execute the app.

IPA files have a built-in directory structure. The example below shows this structure at a high level:

- `/Payload/` folder contains all the application data. We will come back to the contents of this folder in more detail.
- `/Payload/Application.app` contains the application data itself (ARM-compiled code) and associated static resources.
- `/iTunesArtwork` is a 512x512 pixel PNG image used as the application's icon.
- `/iTunesMetadata.plist` contains various bits of information, including the developer's name and ID, the bundle identifier, copyright information, genre, the name of the app, release date, purchase date, etc.
- `/WatchKitSupport/WK` is an example of an extension bundle. This specific bundle contains the extension delegate and the controllers for managing the interfaces and responding to user interactions on an Apple watch.

#### IPA Payloads - A Closer Look

Let's take a closer look at the different files in the IPA container. Apple uses a relatively flat structure with few extraneous directories to save disk space and simplify file access. The top-level bundle directory contains the application's executable file and all the resources the application uses (for example, the application icon, other images, and localized content) .

- **MyApp**: The executable file containing the compiled (unreadable) application source code.
- **Application**: Application icons.
- **Info.plist**: Configuration information, such as bundle ID, version number, and application display name.
- **Launch images**: Images showing the initial application interface in a specific orientation. The system uses one of the provided launch images as a temporary background until the application is fully loaded.
- **MainWindow.nib**: Default interface objects that are loaded when the application is launched. Other interface objects are then either loaded from other nib files or created programmatically by the application.
- **Settings.bundle**: Application-specific preferences to be displayd in the Settings app.
- **Custom resource files**: Non-localized resources are placed in the top-level directory and localized resources are placed in language-specific subdirectories of the application bundle. Resources include nib files, images, sound files, configuration files, strings files, and any other custom data files the application uses.

A language.lproj folder exists for each language that the application supports. It contains a storyboard and strings file.
- A storyboard is a visual representation of the iOS application's user interface. It shows screens and the connections between those screens.
- The strings file format consists of one or more key-value pairs and optional comments.

![iOS App Folder Structure](Images/Chapters/0x06a/iOS_project_folder.png)

On a jailbroken device, you can recover the IPA for an installed iOS app with [IPA Installer](https://github.com/autopear/ipainstaller "IPA Installer"). During mobile security assessments, developers often give you the IPA directly. They can send you the actual file or provide access to the development-specific distribution platform they use, e.g., [HockeyApp](https://hockeyapp.net/ "HockeyApp") or [Testflight](https://developer.apple.com/testflight/ "Testflight").

#### App Structure on the iOS File System

Starting with iOS 8, the way applications are stored on the device changed. Previously, applications were unpacked to a folder in the `/var/mobile/applications/` directory. Applications were identified by UUID (Universal Unique Identifier), a 128-bit number. This number was the name of the folder in which the application itself was stored. Static bundle and application data folders are now stored somewhere else. These folders contain information that must be examined closely during application security assessments.

- `/var/mobile/Containers/Bundle/Application/[UUID]/Application.app` contains the previously mentioned application.app data, and it stores the static content as well as the application's ARM-compiled binary. The contents of this folder is used to validate the code signature.
- `/var/mobile/Containers/Data/Application/[UUID]/Documents` contains all the user-generated data. The application end user initiates the creation of this data.
- `/var/mobile/Containers/Data/Application/[UUID]/Library` contains all files that aren't user-specific, such as caches, preferences, cookies, and property list (plist) configuration files.
- `/var/mobile/Containers/Data/Application/[UUID]/tmp` contains temporary files which aren't needed between application launches.

The following figure represents the application folder structure:
![iOS App Folder Structure](Images/Chapters/0x06a/iOS_Folder_Structure.png)

#### The Installation Process

Different methods exist for installing an IPA package onto an iOS device. The easiest method is iTunes, which is Apple's default media player. iTunes is available for macOS and Windows. iTunes allows users to download applications from the App Store and install them to an iOS device. You can also use [iTunes to install an IPA file to a device](https://www.youtube.com/watch?v=nNn85Qvznug "How to install an app via iTunes").

On Linux, you can use [libimobiledevice](http://www.libimobiledevice.org/ "libimobiledevice"), a cross-platform software protocol library and a set of tools for native communication with iOS devices. You can install packages over an USB connection via ideviceinstaller. The connection is implemented with the USB multiplexing daemon [usbmuxd](https://www.theiphonewiki.com/wiki/Usbmux "Usbmux"), which provides a TCP tunnel over USB.

On the iOS device, the actual installation process is then handled by the installd daemon, which will unpack and install the application. To integrate app services or be installed on an iOS device, all applications must be signed with a certificate issued by Apple. This means that the application can be installed only after successful code signature verification. On a jailbroken phone, however, you can circumvent this security feature with [AppSync](http://repo.hackyouriphone.org/appsyncunified), a package available in the Cydia store. Cydia is an alternative app store. It contains numerous useful applications that leverage jailbreak-provided root privileges  to execute advanced functionality. AppSync is a tweak that patches installd, allowing the installation of fake-signed IPA packages.

The IPA can also be directly installed at the command line by with [ipainstaller](https://github.com/autopear/ipainstaller "IPA Installer"). After you copy the IPA to the device using, for example, scp (secure copy), you can execute the ipainstaller with the IPA's filename:

```bash
$ ipainstaller App_name.ipa
```

#### App Permissions

In contrast to Android apps, iOS apps don't have pre-assigned permissions. Instead, the user is asked to grant permission during run time, when the app attempts to use a sensitive API for the first time. Apps that have been granted permissions are listed in the Settings > Privacy menu, allowing the user to modify the app-specific setting. Apple calls this permission concept [privacy controls](https://support.apple.com/en-sg/HT203033 "Apple - About privacy and Location Services in iOS 8 and later").

iOS developers can't set requested permissions directly—they indirectly request them with sensitive APIs. For example, when accessing a user's contacts, any call to CNContactStore blocks the app while the user is being asked to grant or deny access. Starting with iOS 10.0, apps must include usage description keys for the types of data they need to access (e.g., NSContactsUsageDescription).

The following APIs [require user permission](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide. Page 62"):

- Contacts
- Microphone
- Calendars
- Camera
- Reminders
- HomeKit
- Photos
- Health
- Motion activity and fitness
- Speech recognition
- Location Services
- Bluetooth sharing
- Media Library
- Social media accounts
