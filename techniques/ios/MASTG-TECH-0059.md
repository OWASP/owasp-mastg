---
title: Accessing App Data Directories
platform: ios
---

Once you have installed the app, there is further information to explore. Let's go through a short overview of the app folder structure on iOS apps to understand which data is stored where. The following illustration represents the application folder structure:

<img src="Images/Chapters/0x06a/iOS_Folder_Structure.png" width="400px" />

On iOS, system applications can be found in the `/Applications` directory while user-installed apps are available under `/private/var/containers/`. However, finding the right folder just by navigating the file system is not a trivial task as every app gets a random 128-bit UUID (Universal Unique Identifier) assigned for its directory names.

In order to easily obtain the installation directory information for user-installed apps you can follow the following methods:

Connect to the terminal on the device and use @MASTG-TOOL-0138 to install @MASTG-APP-0028 as follows:

```bash
iPhone:~ root# ipainstaller -l
...
OWASP.iGoat-Swift

iPhone:~ root# ipainstaller -i OWASP.iGoat-Swift
...
Bundle: /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67
Application: /private/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app
Data: /private/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693
```

Using objection's command `env` will also show you all the directory information of the app. Connecting to the application with objection is described in @MASTG-TOOL-0074. In this case we're connecting to @MASTG-APP-0028:

```bash
OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # env

Name               Path
-----------------  -------------------------------------------------------------------------------------------
BundlePath         /var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app
CachesDirectory    /var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/Library/Caches
DocumentDirectory  /var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/Documents
LibraryDirectory   /var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/Library
```

As you can see, apps have two main locations:

- The Bundle directory (`/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/`).
- The Data directory (`/var/mobile/Containers/Data/Application/8C8E7EB0-BC9B-435B-8EF8-8F5560EB0693/`).

These folders contain information that must be examined closely during application security assessments (for example when analyzing the stored data for sensitive data).

Bundle directory:

- **AppName.app**
    - This is the Application Bundle as seen before in the IPA, it contains essential application data, static content as well as the application's compiled binary.
    - This directory is visible to users, but users can't write to it.
    - Content in this directory is not backed up.
    - The contents of this folder are used to validate the code signature.

Data directory:

- **Documents/**
    - Contains all the user-generated data. The application end user initiates the creation of this data.
    - Visible to users and users can write to it.
    - Content in this directory is backed up.
    - The app can disable paths by setting `NSURLIsExcludedFromBackupKey`.
- **Library/**
    - Contains all files that aren't user-specific, such as caches, preferences, cookies, and property list (plist) configuration files.
    - iOS apps usually use the `Application Support` and `Caches` subdirectories, but the app can create custom subdirectories.
- **Library/Caches/**
    - Contains semi-persistent cached files.
    - Invisible to users and users can't write to it.
    - Content in this directory is not backed up.
    - The OS may delete this directory's files automatically when the app is not running and storage space is running low.
- **Library/Application Support/**
    - Contains persistent files necessary for running the app.
    - Invisible to users and users can't write to it.
    - Content in this directory is backed up.
    - The app can disable paths by setting `NSURLIsExcludedFromBackupKey`.
- **Library/Preferences/**
    - Used for storing properties that can persist even after an application is restarted.
    - Information is saved, unencrypted, inside the application sandbox in a plist file called [BUNDLE_ID].plist.
    - All the key/value pairs stored using `NSUserDefaults` can be found in this file.
- **tmp/**
    - Use this directory to write temporary files that do not need to persist between app launches.
    - Contains non-persistent cached files.
    - Invisible to users.
    - Content in this directory is not backed up.
    - The OS may delete this directory's files automatically when the app is not running and storage space is running low.

Let's take a closer look at iGoat-Swift's Application Bundle (.app) directory inside the Bundle directory (`/var/containers/Bundle/Application/3ADAF47D-A734-49FA-B274-FBCA66589E67/iGoat-Swift.app`):

```bash
OWASP.iGoat-Swift on (iPhone: 11.1.2) [usb] # ls
NSFileType      Perms  NSFileProtection    ...  Name
------------  -------  ------------------  ...  --------------------------------------
Regular           420  None                ...  rutger.html
Regular           420  None                ...  mansi.html
Regular           420  None                ...  splash.html
Regular           420  None                ...  about.html

Regular           420  None                ...  LICENSE.txt
Regular           420  None                ...  Sentinel.txt
Regular           420  None                ...  README.txt

Directory         493  None                ...  URLSchemeAttackExerciseVC.nib
Directory         493  None                ...  CutAndPasteExerciseVC.nib
Directory         493  None                ...  RandomKeyGenerationExerciseVC.nib
Directory         493  None                ...  KeychainExerciseVC.nib
Directory         493  None                ...  CoreData.momd
Regular           420  None                ...  archived-expanded-entitlements.xcent
Directory         493  None                ...  SVProgressHUD.bundle

Directory         493  None                ...  Base.lproj
Regular           420  None                ...  Assets.car
Regular           420  None                ...  PkgInfo
Directory         493  None                ...  _CodeSignature
Regular           420  None                ...  AppIcon60x60@3x.png

Directory         493  None                ...  Frameworks

Regular           420  None                ...  embedded.mobileprovision

Regular           420  None                ...  Credentials.plist
Regular           420  None                ...  Assets.plist
Regular           420  None                ...  Info.plist

Regular           493  None                ...  iGoat-Swift
```

You can also visualize the Bundle directory from @MASTG-TOOL-0061 by clicking on **Finder** -> **Bundle**:

<img src="Images/Chapters/0x06b/grapefruit_bundle_dir.png" width="100%" />

Including the `Info.plist` file:

<img src="Images/Chapters/0x06b/grapefruit_plist_view.png" width="100%" />

As well as the Data directory in **Finder** -> **Home**:

<img src="Images/Chapters/0x06b/grapefruit_data_dir.png" width="100%" />

Refer to the [Testing Data Storage](../../Document/0x06d-Testing-Data-Storage.md "Data Storage on iOS") chapter for more information and best practices on securely storing sensitive data.
