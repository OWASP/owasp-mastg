## iOS Platform Overview

iOS is a mobile operating system that powers Apple mobile devices including iPhone, iPad and iPod Touch. It also served the basis for Apple tvOS, which has inherited many of iOS functionalities.
iOS, like Apple desktop operating system, macOS (formerly OS X), is based on Darwin, a hybrid version of XNU kernel. There is an important difference between the two systems: iOS apps run in a more restricted environment than the desktop apps. They are isolated from each other on the file system level, and are significantly limited in terms of system API access.

To protect its users from malicious applications, Apple restricts and controls access to the apps that are allowed to run on iOS devices. Apple App store is the only official application distribution platform where developers can offer their apps and consumers can buy, download and install apps. This is different compared to Android that has several different app stores. Until recently side-loading of apps (or installing an app on your iOS device by bypassing the official App store) was only possible with a jailbreak or complicated workarounds. By using the latest version of Xcode and at least iOS 9 it is possible to do [side-loading via Xcode](https://www.igeeksblog.com/how-to-sideload-apps-on-iphone-ipad-in-ios-10/ "How to Sideload Apps on iPhone and iPad Running iOS 10 using Xcode 8") and install an app directly to your phone.

Sandboxing is mandatory for iOS apps. Apple sandbox (historically called Seatbelt) is a mandatory access control (MAC) mechanisms describing what resources an app can or cannot access. Compared to Android Binder IPC, iOS limits potential attack surface.

Uniform hardware and tight integration between hardware and software brings another security advantage. iOS protects its devices by offering secure boot, hardware-backed keychain and file system encryption. Limited install base allows iOS updates to be rolled out to a large percentage of users quickly that means less need for support of older and unprotected versions of iOS.

In spite of numerous strengths, iOS app developers still need to worry about security. Data protection, Keychain, TouchID authentication and network security still leave plenty of margin for errors. In the following chapters, we are describing iOS security architecture and explaining a basic security testing methodology and reverse engineering how-tos. We are also mapping the categories of MASVS to iOS and outline test cases for each requirement.


### iOS Security Architecture

[iOS security architecture](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "Apple iOS Security Guide") has six core features:

- Hardware Security
- Secure Boot
- Code Signing
- Sandbox
- Encryption and Data Protection
- General Exploit Mitigations

<img src="Images/Chapters/0x06a/iOS_Security_Architecture.png" width="400px"/>
- *iOS Security Architecture*

#### Hardware Security

The iOS security architecture makes heavy use of hardware-based security features that enhance overall performance and security. Each iOS device comes with two built-in AES 256-bit keys – GID and UID – fused and compiled into the application processor and Secure Enclave during manufacturing. There is no direct way to read these keys by software or debugging interfaces such as JTAG. Encryption and decryption operations are performed by hardware AES crypto-engines having exclusive access to these keys.

The GID is a common value shared between all processors in a class of devices and known to Apple, and is used to prevent tampering with firmware files and other cryptographic tasks not directly related to the user's private data. UIDs, which are unique to each device, are used to protect the key hierarchy used for device-level file system encryption. Because they are not recorded during manufacturing, not even Apple can restore the file encryption keys for a particular device.

To enable secure deletion of sensitive data on flash memory, iOS devices include a feature called [Effaceable Storage](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide"). This feature provides direct low-level access to the storage technology, making it possible to securely erase selected blocks.

#### Secure Boot

+When an iOS device is powered on, it reads the initial instructions from the read-only Boot ROM, which bootstraps the system. This memory contains immutable code, together with Apple Root CA, which is etched in the silicon die during fabrication process, creating the root of trust. During the next step, the Boot ROM code checks if the signature of the iBoot bootloader is correct. Once the signature is validated, the iBoot checks the signature of the next boot stage, which is iOS kernel. If any of these steps fail, the boot process is immediately terminated and the device enters the recovery mode and displays the "Connect to iTunes" screen. However, if the Boot ROM fails to load, the device enters a special low level recovery mode, which is called Device Firmware Upgrade (DFU). This is the last resort to recover the device to its original state. In this case the device will have no sign of activity, i.e. its screen will not display anything.
+
+This entire process is called "Secure Boot Chain". It aims at ensuring that the system and its components are written and distributed by Apple. The Secure Boot chain consists of kernel, bootloader, kernel extension and baseband firmware.

#### Code Signing

Signing application code in iOS is different than in Android. In the latter you can sign with a self-signed key and the main purpose would be to establish a root of trust for future application updates. In other words, to make sure that only the original developer of a given application would be able to update it. In Android, applications can be distributed freely as APK files or from Google Play Store. On the contrary, Apple allows app distribution only via App Store.

At least two scenarios exist where you can install an application without the App Store:

1. Via Enterprise Mobile Device Management. This requires the company to have company-wide certificate signed by Apple.
2. Via side-loading, i.e. by signing an app with a developer's certificate and installing it on the device via Xcode. Note that there is an upper limit of the number of devices that can be used with the same certificate.

A developer profile and an Apple-signed certificate are required in order to deploy and run an application.
Developers need to register with Apple and join the [Apple Developer Program](https://developer.apple.com/support/compare-memberships/ "Membership for Apple Developer Program") and pay a yearly subscription fee to get the full range of development and deployment possibilities. A free account still allows you to compile and deploy an application via side-loading.  

Apple has implemented an intricate DRM system to make sure that only valid and approved code runs on Apple devices. In other words, on a non-jailbroken device, one will not be able to run any code unless Apple explicitly allows it. You cannot even opt to run any code on your own device unless you enroll in the Apple developer program and obtain the provisioning profile and signing certificate. For this and other reasons, iOS has been [compared to a crystal prison](https://www.eff.org/deeplinks/2012/05/apples-crystal-prison-and-future-open-platforms "Apple's Crystal Prison and the Future of Open Platforms").
#### Sandbox

The [app sandbox](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html "File System Basics") is an access control technology that was provided for iOS and it is enforced at kernel level. It's purpose is to limit the impact and damage to the system and user data that may occur when an app is compromised.

+Along with the "crystal prison”, sandboxing has been a core security feature since the first releases of iOS. As a principle, all user applications run under the same user `mobile`, with only a few system applications and services running as `root`. Regular apps on iOS are confined to a "container" that restricts access to the app's own files and a very limited amount of system APIs. Access to all resources, like files, network sockets, IPCs, shared memory, etc. will be then controlled by the sandbox. These restrictions work the following ways. [#levin]:

- The app process is restricted to it's own directory (under /var/mobile/Containers/Bundle/Application/) using a chroot-like mechanism.
- The mmap and mmprotect() system calls are modified to prevent apps from make writeable memory pages executable and preventing processes from executing dynamically generated code. In combination with code signing and FairPlay, this enforces strict limitations on what code can be run under specific circumstances (e.g., all code in apps distributed via the app store is approved by Apple).
- Isolation from other running processes, even if they are owned by the same UID.
- Hardware drivers cannot be accessed directly. Instead, any access goes through Apple's frameworks.

#### Encryption and Data Protection

In addition to code signing, *FairPlay Code Encryption* is applied to apps downloaded from the App Store. Originally, FairPlay was developed as a means of DRM for multimedia content purchased via iTunes. In that case, encryption was applied to MPEG and Quicktime streams, but the same basic concepts can also be applied to executable files. The basic idea is as follows: Once you register a new Apple user account, a public/private key pair is created and assigned to your account. The private key is stored securely on your device. This means that Fairplay-encrypted code can be decrypted only on devices associated with your account -- TODO [Be more specific] --. The usual way to obtain reverse FairPlay encryption is to run the app on the device and then dump the decrypted code from memory (see also "Basic Security Testing on iOS").

Apple has built encryption into the hardware and firmware of its iOS devices since the release of the iPhone 3GS. Every device has a dedicated hardware level based crypto engine, based on 256-bit Advanced Encryption Standard (AES), that works in conjunction with a SHA-1 cryptographic hash function.

Besides that, there is unique identifier (UID) built into the device's hardware with an AES 256-bit key fused into the application processor. This UID is specific to the device and is not recorded elsewhere. As of this writing, it is not possible for software or firmware to read it directly. As the key is burnt into the silicon chip, it cannot be tampered with or bypassed. It is only the crypto engine which can access it.

Building encryption into the physical architecture makes it a default security control that is able to encrypt all data stored on an iOS device. As a result data protection is implemented at the software level and works with the hardware and firmware encryption to provide a greater degree of security.

+When data protection is enabled, each data file is associated with a specific class that supports a different level of accessibility and protects data based on when it needs to be accessed. The encryption and decryption operations associated with each class are based on multiple key mechanisms that utilizes the device's UID and passcode, plus a class key, file system key and per-file key. The per-file key is used to encrypt the file content. The class key is wrapped around the per file key and stored in the file's metadata. The file system key is used to encrypt the metadata. The UID and passcode protect the class key. This operation is invisible to users. The passcode must be used when accessing the device to enable data protection. The passcode does not only unlock the device, but also combined with the UID creates iOS encryption keys that are more resistant to hacking efforts and brute-force attacks. Enabling data protection is the main reason for users to use passcodes on their devices.

#### General Exploit Mitigations

iOS currently implements two specific security mechanisms, namely address space layout randomization (ASLR) and eXecute Never (XN) bit, to prevent code execution attacks.

ASLR is a technique that does the job of randomizing the memory location of the program executable, data, heap and stack on every execution of the program. As the shared libraries need to be static in order to be shared by multiple processes, the addresses of shared libraries are randomized every time the OS boots instead of every time when the program is invoked. Thus, this makes specific memory addresses of functions and libraries hard to predict, thereby preventing attacks such as a return-to-libc attack, which relies upon the memory addresses of basic libc functions.

<!-- TODO [Further develop section on iOS General Exploit Mitigation] -->
The XN mechanism allows iOS to mark certain memory segments as non-executable on a program’s stack and heap by default. In case of an attack this will prevent malicious code inserted onto the stack or heap from execution.

### Software Development on iOS

Like other platforms, Apple provides a Software Development Kit (SDK) for iOS that helps developers to develop, install, run and test native iOS Apps by offering different tools and interfaces. Xcode is an Integrated Development Environment (IDE) used for this purpose. iOS applications are developed either by using Objective-C or Swift.

Objective-C is an object-oriented programming language that adds Smalltalk-style messaging to the C programming language. It is used on macOS and iOS to develop desktop and mobile applications respectively. Swift is the successor of Objective-C and allows interoperability with it. Swift was introduced with Xcode 6 in 2014.

### Understanding iOS Apps

iOS applications are distributed in IPA (iOS App Store Package) archives. An IPA file contains all the necessary (for ARM compiled) application code and resources required to execute the application. This package is in fact a ZIP compressed file, which can be decompressed.

An IPA file has a built-in directory structure. The example below shows this structure on a high level:

- `/Payload/` folder contains all the application data. We will come back to the content of this folder in more detail.
- `/Payload/Application.app` contains the application data itself (ARM compiled code) and associated static resources.
- `/iTunesArtwork` is a 512x512 pixel PNG image used as the application’s icon.
- `/iTunesMetadata.plist` contains various bits of information, ranging from the developer's name and ID, the bundle identifier, copyright information, genre, the name of the app, release date, purchase date, etc.
- `/WatchKitSupport/WK` is an example of an extension bundle. This specific bundle contains the extension delegate and the controllers for managing the interfaces and for responding to user interactions on an Apple watch.

#### IPA Payloads - A Closer Look

Let us take a closer look at the different files that can be found in the IPA container. It is necessary to understand that this is the raw architecture of the bundle container and not the definitive form after its installation on a device. It uses a relatively flat structure with few extraneous directories in an effort to save disk space and simplify access to the files. The bundle contains the application executable and any resources used by the application (for instance, the application icon, other images, and localized content) in the top-level bundle directory.

- **MyApp**: The executable containing the application code, which is compiled and not in a ‘readable’ format.
- **Application**: Icons used at specific times to represent the application.
- **Info.plist**: Configuration information, such as its bundle ID, version number, and application display name.
- **Launch images**: Images showing the initial interface of the application in a specific orientation. The system uses one of the provided launch images as a temporary background until the application is fully loaded.
- **MainWindow.nib**: Default interface objects to load at application launch time. Other interface objects are then either loaded from additional nib files or created programmatically by the application.
- **Settings.bundle**: Application-specific preferences using property lists and other resource files to be configured and displayed.
- **Custom resource files**: Non-localized resources are placed at the top-level directory and localized resources are placed in language-specific subdirectories of the application bundle. Resources include nib files, images, sound files, configuration files, strings files and any other custom data files used by the application.

A language.lproj folder is defined for each language that the application supports. It contains a storyboard and strings file.
- A storyboard is a visual representation of the user interface of an iOS application, showing screens of content and the connections between those screens.
- The strings file format consists of one or more key-value pairs along with optional comments.

<img src="Images/Chapters/0x06a/iOS_project_folder.png" width="500px"/>
- *iOS App Folder Structure*

On a jailbroken device, you can recover the IPA for an installed iOS app using [IPA Installer](https://github.com/autopear/ipainstaller "IPA Installer"). Note that during mobile security assessments, developers will often provide you with the IPA directly. They can send you the actual file, or provide access to the development specific distribution platform they use e.g. [HockeyApp](https://hockeyapp.net/ "HockeyApp") or [Testflight](https://developer.apple.com/testflight/ "Testflight").



#### App Structure on the iOS File System

Since iOS 8, changes were made to the way an application is stored on the device. On versions before iOS 8, applications would be unpacked to a folder in the /var/mobile/applications/. The application would be identified by its UUID (Universal Unique Identifier), a 128-bit number. This would be the name of the folder in which we will find the application itself. Since the iOS 8 release static bundle and application data folders are now stored in different locations in the file system. These folders contain information that must be closely examined during application security assessments.

- `/var/mobile/Containers/Bundle/Application/[UUID]/Application.app` contains the previously mentioned application.app data and stores the static content as well as the ARM compiled binary of the application. The content of this folder will be used to validate the code signature.
- `/var/mobile/Containers/Data/Application/[UUID]/Documents` contains all the user generated data. The creation of this data is initiated by the application end user.
- `/var/mobile/Containers/Data/Application/[UUID]/Library` contains all non user-specific files, like caches, preferences, cookies, property list (plist) configuration files, etc.
- `/var/mobile/Containers/Data/Application/[UUID]/tmp` contains temporary files which are not needed between application launches.

The following figure represents the application folder structure:

<img src="/Images/Chapters/0x06a/iOS_Folder_Structure.png" width="500px"/>
- *iOS App Folder Structure*

#### The Installation Process

Different methods exist to install an IPA package on an iOS device. The easiest solution is to use iTunes, which is the default media player from Apple. iTunes is available for macOS as well as for Windows. iTunes allows users to download applications through the App Store and install them to the iOS device. You can also use [iTunes to install an IPA file to a device](https://www.youtube.com/watch?v=nNn85Qvznug "How to install an app via iTunes").

On Linux you can make use of [libimobiledevice](http://www.libimobiledevice.org/ "libimobiledevice"), a cross-platform software protocol library and set of tools to communicate with iOS devices natively. Packages can be installed to the device via ideviceinstaller over an USB connection. The connection is implemented by using the USB multiplexing daemon [usbmuxd](https://www.theiphonewiki.com/wiki/Usbmux "Usbmux"), which provides a TCP tunnel over USB.

iOS developers don't have the possibility to set requested permissions directly – they are requesting them indirectly by using sensitive APIs. For example, when accessing user's contacts, any call to CNContactStore blocks the app while the user is being asked to grant or deny access. Starting with iOS 10.0, apps must include usage description keys for the types of data they need to access (e.g. NSContactsUsageDescription).

On the iOS device, the actual installation process is then handled by installd daemon, which will unpack and install the application. Any application must be signed with a certificate issued by Apple to be able to integrate app services or be installed on an iOS device. This means that the application we can only be installed after the successful code signature verification. On a jailbroken phone this can however be circumvented using [AppSync](https://cydia.angelxwind.net/?page/net.angelxwind.appsyncunified), a package made available on the Cydia store. This is an alternative app store containing numerous useful applications which leverage root privileges provided through the jailbreak in order to execute advanced functionalities. AppSync is a tweak that patches installd to allow the installation of fake-signed IPA packages.

The IPA can also be installed directly from command line by using [ipainstaller](https://github.com/autopear/ipainstaller "IPA Installer"). After copying the IPA onto the device, for example by using scp (secure copy), the ipainstaller can be executed with the filename of the IPA:

```bash
$ ipainstaller App_name.ipa
```

#### App Permissions

In contrast to Android, iOS applications do not have preassigned permissions. Instead, the user is asked to grant permission during runtime when the app attempts to use a sensitive API for the first time. Once the app has asked for a permission, it is listed in the Settings > Privacy menu, allowing the user to modify the app-specific setting. Apple calls this permission concept [privacy controls](https://support.apple.com/en-sg/HT203033 "Apple - About privacy and Location Services in iOS 8 and later").

iOS developers don't have the possibility to set requested permissions directly – they are requesting them indirectly by using sensitive APIs. For example, when accessing user's contacts, any call to CNContactStore blocks the app while the user is being asked to grant or deny access. Starting with iOS 10.0, apps must include usage description keys for the types of data they need to access (e.g. NSContactsUsageDescription).

The following APIs [require permission from the user](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide. Page 62"):

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
