---
title: Exploring the App Package
platform: ios
---

Once you have collected the package name of the application you want to target, you'll want to start gathering information about it. First, retrieve the @MASTG-APP-0028 IPA as explained in @MASTG-TECH-0054.

You can unzip the IPA using the standard `unzip` or any other ZIP utility.

```bash
unzip iGoat-Swift.ipa
```

Inside you'll find a `Payload` folder containing the so-called Application Bundle (.app). The following is an example in the following output, note that it was truncated for better readability and overview:

```bash
$ ls -1 Payload/iGoat-Swift.app
rutger.html
mansi.html
splash.html
about.html

LICENSE.txt
Sentinel.txt
README.txt

URLSchemeAttackExerciseVC.nib
CutAndPasteExerciseVC.nib
RandomKeyGenerationExerciseVC.nib
KeychainExerciseVC.nib
CoreData.momd
archived-expanded-entitlements.xcent
SVProgressHUD.bundle

Base.lproj
Assets.car
PkgInfo
_CodeSignature
AppIcon60x60@3x.png

Frameworks

embedded.mobileprovision

Credentials.plist
Assets.plist
Info.plist

iGoat-Swift
```

The most relevant items are:

- `Info.plist` contains configuration information for the application, such as its bundle ID, version number, and display name.
- `_CodeSignature/` contains a plist file with a signature over all files in the bundle.
- `Frameworks/` contains the app native libraries as .dylib or .framework files.
- `PlugIns/` may contain app extensions as .appex files (not present in the example).
- iGoat-Swift is the app binary containing the app's code. Its name is the same as the bundle's name minus the .app extension.
- Various resources such as images/icons, `*.nib` files (storing the user interfaces of iOS app), localized content (`<language>.lproj`), text files, audio files, etc.

## The Info.plist File

The information property list or `Info.plist` (named by convention) is the main source of information for an iOS app. It consists of a structured file containing key-value pairs describing essential configuration information about the app. Actually, all bundled executables (app extensions, frameworks and apps) are expected to have an `Info.plist` file. You can find all possible keys in the [Apple Developer Documentation](https://developer.apple.com/documentation/bundleresources/information_property_list?language=objc "Information Property List").

The file might be formatted in XML or binary (bplist). You can convert it to XML format with one simple command:

- On macOS with `plutil`, which is a tool that comes natively with macOS 10.2 and above versions (no official online documentation is currently available):

  ```bash
  plutil -convert xml1 Info.plist
  ```

- On Linux:

  ```bash
  apt install libplist-utils
  plistutil -i Info.plist -o Info_xml.plist
  ```

Here's a non-exhaustive list of some info and the corresponding keywords that you can easily search for in the `Info.plist` file by just inspecting the file or by using `grep -i <keyword> Info.plist`:

- App permissions Purpose Strings: `UsageDescription` (see "[iOS Platform APIs](../../Document/0x06h-Testing-Platform-Interaction.md)")
- Custom URL schemes: `CFBundleURLTypes` (see "[iOS Platform APIs](../../Document/0x06h-Testing-Platform-Interaction.md)")
- Exported/imported _custom document types_: `UTExportedTypeDeclarations` / `UTImportedTypeDeclarations` (see "[iOS Platform APIs](../../Document/0x06h-Testing-Platform-Interaction.md)")
- App Transport Security (ATS) configuration: `NSAppTransportSecurity` (see "[iOS Network Communication](../../Document/0x06g-Testing-Network-Communication.md)")

Please refer to the mentioned chapters to learn more about how to test each of these points.

## App Binary

iOS app binaries are fat binaries (they can be deployed on all devices 32- and 64-bit). In contrast to Android, where you can actually decompile the app binary to Java code, the iOS app binaries can only be disassembled.

## Native Libraries

iOS apps can make their codebase modular by using different elements. In the MASTG we will refer to all of them as native libraries, but they can come in different forms:

- [Static and Dynamic Libraries](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/OverviewOfDynamicLibraries.html#//apple_ref/doc/uid/TP40001873-SW1):
    - Static Libraries can be used and will be compiled in the app binary.
    - Dynamic Libraries (typically having the `.dylib` extension) are also used but must be part of a framework bundle. Standalone Dynamic Libraries are [not supported](https://developer.apple.com/library/archive/technotes/tn2435/_index.html#//apple_ref/doc/uid/DTS40017543-CH1-PROJ_CONFIG-APPS_WITH_DEPENDENCIES_BETWEEN_FRAMEWORKS) on iOS, watchOS, or tvOS, except for the system Swift libraries provided by Xcode.
- [Frameworks](https://developer.apple.com/library/archive/technotes/tn2435/_index.html#//apple_ref/doc/uid/DTS40017543-CH1-PROJ_CONFIG-APPS_WITH_DEPENDENCIES_BETWEEN_FRAMEWORKS) (since iOS 8). A Framework is a hierarchical directory that encapsulates a dynamic library, header files, and resources, such as storyboards, image files, and localized strings, into a single package.
- [Binary Frameworks (`XCFrameworks`)](https://developer.apple.com/videos/play/wwdc2019/416/): Xcode 11 supports distributing binary libraries using the `XCFrameworks` format which is a new way to bundle up multiple variants of a Framework, e.g. for any of the platforms that Xcode supports (including simulator and devices). They can also bundle up static libraries (and their corresponding headers) and support binary distribution of Swift and C-based code. `XCFrameworks` can be [distributed as Swift Packages](https://developer.apple.com/documentation/xcode/distributing-binary-frameworks-as-swift-packages).
- [Swift Packages](https://developer.apple.com/documentation/xcode/swift-packages): Xcode 11 add supports for Swift packages, which are reusable components of Swift, Objective-C, Objective-C++, C, or C++ code that developers can use in their projects and are distributed as source code. Since Xcode 12 they can also [bundle resources](https://developer.apple.com/videos/play/wwdc2020/10169/), such as images, storyboards, and other files. Since Package libraries are [static by default](https://developer.apple.com/videos/play/wwdc2019/408/?time=739). Xcode compiles them, and the packages they depend on, and then links and combines everything into the application.

You can view native libraries in @MASTG-TOOL-0061 by clicking on the Modules icon in the left menu bar:

<img src="Images/Chapters/0x06b/grapefruit_modules.png" width="100%" />

And get a more detailed view including their imports/exports:

<img src="Images/Chapters/0x06b/grapefruit_modules_detail.png" width="100%" />

They are available in the `Frameworks` folder in the IPA, you can also inspect them from the terminal:

```bash
$ ls -1 Frameworks/
Realm.framework
libswiftCore.dylib
libswiftCoreData.dylib
libswiftCoreFoundation.dylib
```

or from the device with objection (as well as per SSH of course):

```bash
OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # ls
NSFileType      Perms  NSFileProtection    ...  Name
------------  -------  ------------------  ...  ----------------------------
Directory         493  None                ...  Realm.framework
Regular           420  None                ...  libswiftCore.dylib
Regular           420  None                ...  libswiftCoreData.dylib
Regular           420  None                ...  libswiftCoreFoundation.dylib
...
```

Please note that this might not be the complete list of native code elements being used by the app as some can be part of the source code, meaning that they'll be compiled in the app binary and therefore cannot be found as standalone libraries or Frameworks in the `Frameworks` folder.

For now this is all information you can get about the Frameworks unless you start reverse engineering them. Refer to for more information about how to reverse engineer Frameworks.

## Other App Resources

It is normally worth taking a look at the rest of the resources and files that you may find in the Application Bundle (.app) inside the IPA as some times they contain additional goodies like encrypted databases, certificates, etc.

<img src="Images/Chapters/0x06b/grapefruit_db_view.png" width="100%" />
