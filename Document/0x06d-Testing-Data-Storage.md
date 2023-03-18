# iOS Data Storage

The protection of sensitive data, such as authentication tokens and private information, is key for mobile security. In this chapter, you'll learn about the iOS APIs for local data storage, and best practices for using them.

As little sensitive data as possible should be saved in permanent local storage. However, in most practical scenarios, at least some user data must be stored. Fortunately, iOS offers secure storage APIs, which allow developers to use the cryptographic hardware available on every iOS device. If these APIs are used correctly, sensitive data and files can be secured via hardware-backed 256-bit AES encryption.

## Overview

### NSData and NSMutableData

`NSData` (static data objects) and `NSMutableData` (dynamic data objects) are typically used for data storage, but they are also useful for distributed objects applications, in which data contained in data objects can be copied or moved between applications. The following are methods used to write `NSData` objects:

- `NSDataWritingWithoutOverwriting`
- `NSDataWritingFileProtectionNone`
- `NSDataWritingFileProtectionComplete`
- `NSDataWritingFileProtectionCompleteUnlessOpen`
- `NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication`
- `writeToFile`: stores data as part of the `NSData` class
- `NSSearchPathForDirectoriesInDomains, NSTemporaryDirectory`: used to manage file paths
- `NSFileManager`: lets you examine and change the contents of the file system. You can use `createFileAtPath` to create a file and write to it.

The following example shows how to create a `complete` encrypted file using the `FileManager` class. You can find more information in the Apple Developer Documentation ["Encrypting Your App's Files"](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files "Encrypting Your App's Files")

Swift:

```swift
FileManager.default.createFile(
    atPath: filePath,
    contents: "secret text".data(using: .utf8),
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

Objective-C:

```objectivec
[[NSFileManager defaultManager] createFileAtPath:[self filePath]
  contents:[@"secret text" dataUsingEncoding:NSUTF8StringEncoding]
  attributes:[NSDictionary dictionaryWithObject:NSFileProtectionComplete
  forKey:NSFileProtectionKey]];
```

### NSUserDefaults

The [`NSUserDefaults`](https://developer.apple.com/documentation/foundation/nsuserdefaults "NSUserDefaults Class") class provides a programmatic interface for interacting with the default system. The default system allows an application to customize its behavior according to user preferences. Data saved by `NSUserDefaults` can be viewed in the application bundle. This class stores data in a plist file, but it's meant to be used with small amounts of data.

### Databases

#### CoreData

[`Core Data`](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/CoreData/nsfetchedresultscontroller.html#//apple_ref/doc/uid/TP40001075-CH8-SW1 "Core Data iOS") is a framework for managing the model layer of objects in your application. It provides general and automated solutions to common tasks associated with object life cycles and object graph management, including persistence. [Core Data can use SQLite as its persistent store](https://cocoacasts.com/what-is-the-difference-between-core-data-and-sqlite/ "What Is the Difference Between Core Data and SQLite"), but the framework itself is not a database.

CoreData does not encrypt it's data by default. As part of a research project (iMAS) from the MITRE Corporation, that was focused on open source iOS security controls, an additional encryption layer can be added to CoreData. See the [GitHub Repo](https://github.com/project-imas/encrypted-core-data "Encrypted Core Data SQLite Store") for more details.

#### SQLite Databases

The SQLite 3 library must be added to an app if the app is to use SQLite. This library is a C++ wrapper that provides an API for the SQLite commands.

#### Firebase Real-time Databases

Firebase is a development platform with more than 15 products, and one of them is Firebase Real-time Database. It can be leveraged by application developers to store and sync data with a NoSQL cloud-hosted database. The data is stored as JSON and is synchronized in real-time to every connected client and also remains available even when the application goes offline.

A misconfigured Firebase instance can be identified by making the following network call:

`https://\<firebaseProjectName\>.firebaseio.com/.json`

The _firebaseProjectName_ can be retrieved from the property list(.plist) file. For example, `PROJECT_ID` key stores the corresponding Firebase project name in _GoogleService-Info.plist_ file.

Alternatively, the analysts can use [Firebase Scanner](https://github.com/shivsahni/FireBaseScanner "Firebase Scanner"), a python script that automates the task above as shown below:

```bash
python FirebaseScanner.py -f <commaSeparatedFirebaseProjectNames>
```

#### Realm Databases

[Realm Objective-C](https://realm.io/docs/objc/latest/ "Realm Objective-C") and [Realm Swift](https://realm.io/docs/swift/latest/ "Realm Swift") aren't supplied by Apple, but they are still worth noting. They store everything unencrypted, unless the configuration has encryption enabled.

The following example demonstrates how to use encryption with a Realm database:

```swift
// Open the encrypted Realm file where getKey() is a method to obtain a key from the Keychain or a server
let config = Realm.Configuration(encryptionKey: getKey())
do {
  let realm = try Realm(configuration: config)
  // Use the Realm as normal
} catch let error as NSError {
  // If the encryption key is wrong, `error` will say that it's an invalid database
  fatalError("Error opening realm: \(error)")
}
```

#### Couchbase Lite Databases

[Couchbase Lite](https://github.com/couchbase/couchbase-lite-ios "Couchbase Lite") is a lightweight, embedded, document-oriented (NoSQL) database engine that can be synced. It compiles natively for iOS and macOS.

#### YapDatabase

[YapDatabase](https://github.com/yapstudios/YapDatabase "YapDatabase") is a key/value store built on top of SQLite.

### User Interface

#### UI Components

Entering sensitive information when, for example, registering an account or making payments, is an essential part of using many apps. This data may be financial information such as credit card data or user account passwords. The data may be exposed if the app doesn't properly mask it while it is being typed.

In order to prevent disclosure and mitigate risks such as [shoulder surfing](https://en.wikipedia.org/wiki/Shoulder_surfing_%28computer_security%29) you should verify that no sensitive data is exposed via the user interface unless explicitly required (e.g. a password being entered). For the data required to be present it should be properly masked, typically by showing asterisks or dots instead of clear text.

Carefully review all UI components that either show such information or take it as input. Search for any traces of sensitive information and evaluate if it should be masked or completely removed.

#### Screenshots

Manufacturers want to provide device users with an aesthetically pleasing effect when an application is started or exited, so they introduced the concept of saving a screenshot when the application goes into the background. This feature can pose a security risk because screenshots (which may display sensitive information such as an email or corporate documents) are written to local storage, where they can be recovered by a rogue application with a sandbox bypass exploit or someone who steals the device.

#### Keyboard Cache

Several options for simplifying keyboard input are available to users. These options include autocorrection and spell checking. Most keyboard input is cached by default, in `/private/var/mobile/Library/Keyboard/dynamic-text.dat`.

The [UITextInputTraits protocol](https://developer.apple.com/reference/uikit/uitextinputtraits "UITextInputTraits protocol") is used for keyboard caching. The `UITextField`, `UITextView`, and `UISearchBar` classes automatically support this protocol and it offers the following properties:

- `var autocorrectionType: UITextAutocorrectionType` determines whether autocorrection is enabled during typing. When autocorrection is enabled, the text object tracks unknown words and suggests suitable replacements, replacing the typed text automatically unless the user overrides the replacement. The default value of this property is `UITextAutocorrectionTypeDefault`, which for most input methods enables autocorrection.
- `var secureTextEntry: BOOL` determines whether text copying and text caching are disabled and hides the text being entered for `UITextField`. The default value of this property is `NO`.

### Internal Storage

#### Data Protection API

App developers can leverage the iOS _Data Protection_ APIs to implement fine-grained access control for user data stored in flash memory. The APIs are built on top of the Secure Enclave Processor (SEP), which was introduced with the iPhone 5S. The SEP is a coprocessor that provides cryptographic operations for data protection and key management. A device-specific hardware key-the device UID (Unique ID)-is embedded in the secure enclave, ensuring the integrity of data protection even when the operating system kernel is compromised.

> You can learn more about the Secure Enclave in this BlackHat presentation ["Demystifying the Secure Enclave Processor"](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf) by Tarjei Mandt, Mathew Solnik and David Wang.

The data protection architecture is based on a hierarchy of keys. The UID and the user passcode key (which is derived from the user's passphrase via the PBKDF2 algorithm) sit at the top of this hierarchy. Together, they can be used to "unlock" so-called class keys, which are associated with different device states (e.g., device locked/unlocked).

Every file stored on the iOS file system is encrypted with its own per-file key, which is contained in the file metadata. The metadata is encrypted with the file system key and wrapped with the class key corresponding to the protection class the app selected when creating the file.

The following illustration shows the [iOS Data Protection Key Hierarchy](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide").

<img src="Images/Chapters/0x06d/key_hierarchy_apple.jpg" width="100%" />

Files can be assigned to one of four different protection classes, which are explained in more detail in the [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide"):

- **Complete Protection (NSFileProtectionComplete)**: A key derived from the user passcode and the device UID protects this class key. The derived key is wiped from memory shortly after the device is locked, making the data inaccessible until the user unlocks the device.

- **Protected Unless Open (NSFileProtectionCompleteUnlessOpen)**: This protection class is similar to Complete Protection, but, if the file is opened when unlocked, the app can continue to access the file even if the user locks the device. This protection class is used when, for example, a mail attachment is downloading in the background.

- **Protected Until First User Authentication (NSFileProtectionCompleteUntilFirstUserAuthentication)**: The file can be accessed as soon as the user unlocks the device for the first time after booting. It can be accessed even if the user subsequently locks the device and the class key is not removed from memory.

- **No Protection (NSFileProtectionNone)**: The key for this protection class is protected with the UID only. The class key is stored in "Effaceable Storage", which is a region of flash memory on the iOS device that allows the storage of small amounts of data. This protection class exists for fast remote wiping (immediate deletion of the class key, which makes the data inaccessible).

All class keys except `NSFileProtectionNone` are encrypted with a key derived from the device UID and the user's passcode. As a result, decryption can happen only on the device itself and requires the correct passcode.

Since iOS 7, the default data protection class is "Protected Until First User Authentication".

### External Storage

### The Keychain

The iOS Keychain can be used to securely store short, sensitive bits of data, such as encryption keys and session tokens. It is implemented as an SQLite database that can be accessed through the Keychain APIs only.

On macOS, every user application can create as many Keychains as desired, and every login account has its own Keychain. The [structure of the Keychain on iOS](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html "https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html") is different: only one Keychain is available to all apps. Access to the items can be shared between apps signed by the same developer via the [access groups feature](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/AddingCapabilities/AddingCapabilities.html "Adding capabilities") of the attribute [`kSecAttrAccessGroup`](https://developer.apple.com/documentation/security/ksecattraccessgroup "Attribute kSecAttrAccessGroup"). Access to the Keychain is managed by the `securityd` daemon, which grants access according to the app's `Keychain-access-groups`, `application-identifier`, and `application-group` entitlements.

The [Keychain API](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html "Keychain concepts") includes the following main operations:

- `SecItemAdd`
- `SecItemUpdate`
- `SecItemCopyMatching`
- `SecItemDelete`

Data stored in the Keychain is protected via a class structure that is similar to the class structure used for file encryption. Items added to the Keychain are encoded as a binary plist and encrypted with a 128-bit AES per-item key in Galois/Counter Mode (GCM). Note that larger blobs of data aren't meant to be saved directly in the Keychain-that's what the Data Protection API is for. You can configure data protection for Keychain items by setting the `kSecAttrAccessible` key in the call to `SecItemAdd` or `SecItemUpdate`. The following configurable [accessibility values for kSecAttrAccessible](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values#1679100 "Accessibility Values for kSecAttrAccessible") are the Keychain Data Protection classes:

- `kSecAttrAccessibleAlways`: The data in the Keychain item can always be accessed, regardless of whether the device is locked.
- `kSecAttrAccessibleAlwaysThisDeviceOnly`: The data in the Keychain item can always be accessed, regardless of whether the device is locked. The data won't be included in an iCloud or local backup.
- `kSecAttrAccessibleAfterFirstUnlock`: The data in the Keychain item can't be accessed after a restart until the device has been unlocked once by the user.
- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: The data in the Keychain item can't be accessed after a restart until the device has been unlocked once by the user. Items with this attribute do not migrate to a new device. Thus, after restoring from a backup of a different device, these items will not be present.
- `kSecAttrAccessibleWhenUnlocked`: The data in the Keychain item can be accessed only while the device is unlocked by the user.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: The data in the Keychain item can be accessed only while the device is unlocked by the user. The data won't be included in an iCloud or local backup.
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: The data in the Keychain can be accessed only when the device is unlocked. This protection class is only available if a passcode is set on the device. The data won't be included in an iCloud or local backup.

`AccessControlFlags` define the mechanisms with which users can authenticate the key (`SecAccessControlCreateFlags`):

- `kSecAccessControlDevicePasscode`: Access the item via a passcode.
- `kSecAccessControlBiometryAny`: Access the item via one of the fingerprints registered to Touch ID. Adding or removing a fingerprint won't invalidate the item.
- `kSecAccessControlBiometryCurrentSet`: Access the item via one of the fingerprints registered to Touch ID. Adding or removing a fingerprint _will_ invalidate the item.
- `kSecAccessControlUserPresence`: Access the item via either one of the registered fingerprints (using Touch ID) or default to the passcode.

Please note that keys secured by Touch ID (via `kSecAccessControlBiometryAny` or `kSecAccessControlBiometryCurrentSet`) are protected by the Secure Enclave: The Keychain holds a token only, not the actual key. The key resides in the Secure Enclave.

Starting with iOS 9, you can do ECC-based signing operations in the Secure Enclave. In that scenario, the private key and the cryptographic operations reside within the Secure Enclave. See the static analysis section for more info on creating the ECC keys.
iOS 9 supports only 256-bit ECC. Furthermore, you need to store the public key in the Keychain because it can't be stored in the Secure Enclave. After the key is created, you can use the `kSecAttrKeyType` to indicate the type of algorithm you want to use the key with.

In case you want to use these mechanisms, it is recommended to test whether the passcode has been set. In iOS 8, you will need to check whether you can read/write from an item in the Keychain protected by the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` attribute. From iOS 9 onward you can check whether a lock screen is set, using `LAContext`:

Swift:

```swift
public func devicePasscodeEnabled() -> Bool {
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
}
```

Objective-C:

```objectivec
-(BOOL)devicePasscodeEnabled:(LAContext)context{
  if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil]) {
        return true;
    } else {
        return false;
    }
}
```

Here is sample Swift code you can use to create keys (Notice the `kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave`: this indicates that we want to use the Secure Enclave directly.):

```swift
// private key parameters
let privateKeyParams = [
    kSecAttrLabel as String: "privateLabel",
    kSecAttrIsPermanent as String: true,
    kSecAttrApplicationTag as String: "applicationTag",
] as CFDictionary

// public key parameters
let publicKeyParams = [
    kSecAttrLabel as String: "publicLabel",
    kSecAttrIsPermanent as String: false,
    kSecAttrApplicationTag as String: "applicationTag",
] as CFDictionary

// global parameters
let parameters = [
    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPublicKeyAttrs as String: publicKeyParams,
    kSecPrivateKeyAttrs as String: privateKeyParams,
] as CFDictionary

var pubKey, privKey: SecKey?
let status = SecKeyGeneratePair(parameters, &pubKey, &privKey)

if status != errSecSuccess {
    // Keys created successfully
}
```

#### Keychain Data Persistence

On iOS, when an application is uninstalled, the Keychain data used by the application is retained by the device, unlike the data stored by the application sandbox which is wiped. In the event that a user sells their device without performing a factory reset, the buyer of the device may be able to gain access to the previous user's application accounts and data by reinstalling the same applications used by the previous user. This would require no technical ability to perform.

When assessing an iOS application, you should look for Keychain data persistence. This is normally done by using the application to generate sample data that may be stored in the Keychain, uninstalling the application, then reinstalling the application to see whether the data was retained between application installations. Use objection runtime mobile exploration toolkit to dump the keychain data. The following `objection` command demonstrates this procedure:

```bash
...itudehacks.DVIAswiftv2.develop on (iPhone: 13.2.3) [usb] # ios keychain dump
Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created                    Accessible                      ACL    Type      Account                    Service                                                        Data
-------------------------  ------------------------------  -----  --------  -------------------------  -------------------------------------------------------------  ------------------------------------
2020-02-11 13:26:52 +0000  WhenUnlocked                    None   Password  keychainValue              com.highaltitudehacks.DVIAswiftv2.develop                      mysecretpass123
```  

There's no iOS API that developers can use to force wipe data when an application is uninstalled. Instead, developers should take the following steps to prevent Keychain data from persisting between application installations:

- When an application is first launched after installation, wipe all Keychain data associated with the application. This will prevent a device's second user from accidentally gaining access to the previous user's accounts. The following Swift example is a basic demonstration of this wiping procedure:

```swift
let userDefaults = UserDefaults.standard

if userDefaults.bool(forKey: "hasRunBefore") == false {
    // Remove Keychain items here

    // Update the flag indicator
    userDefaults.set(true, forKey: "hasRunBefore")
}
```

- When developing logout functionality for an iOS application, make sure that the Keychain data is wiped as part of account logout. This will allow users to clear their accounts before uninstalling an application.

### Logs

There are many legitimate reasons for creating log files on a mobile device, including keeping track of crashes or errors that are stored locally while the device is offline (so that they can be sent to the app's developer once online), and storing usage statistics. However, logging sensitive data, such as credit card numbers and session information, may expose the data to attackers or malicious applications.
Log files can be created in several ways. The following list shows the methods available on iOS:

- NSLog Method
- printf-like function
- NSAssert-like function
- Macro

### Backups

iOS includes auto-backup features that create copies of the data stored on the device. You can make iOS backups from your host computer by using iTunes (till macOS Catalina) or Finder (from macOS Catalina onwards), or via the iCloud backup feature. In both cases, the backup includes nearly all data stored on the iOS device except highly sensitive data such as Apple Pay information and Touch ID settings.

Since iOS backs up installed apps and their data, an obvious concern is whether sensitive user data stored by the app might unintentionally leak through the backup. Another concern, though less obvious, is whether sensitive configuration settings used to protect data or restrict app functionality could be tampered to change app behavior after restoring a modified backup. Both concerns are valid and these vulnerabilities have proven to exist in a vast number of apps today.

#### How the Keychain Is Backed Up

When users back up their iOS device, the Keychain data is backed up as well, but the secrets in the Keychain remain encrypted. The class keys necessary to decrypt the Keychain data aren't included in the backup. Restoring the Keychain data requires restoring the backup to a device and unlocking the device with the users passcode.

Keychain items for which the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` attribute is set can be decrypted only if the backup is restored to the backed up device. Someone trying to extract this Keychain data from the backup couldn't decrypt it without access to the crypto hardware inside the originating device.

One caveat to using the Keychain, however, is that it was only designed to store small bits of user data or short notes (according to Apple's documentation on [Keychain Services](https://developer.apple.com/documentation/security/keychain_services "Keychain Services")). This means that apps with larger local secure storage needs (e.g., messaging apps, etc.) should encrypt the data within the app container, but use the Keychain to store key material. In cases where sensitive configuration settings (e.g., data loss prevention policies, password policies, compliance policies, etc) must remain unencrypted within the app container, you can consider storing a hash of the policies in the keychain for integrity checking. Without an integrity check, these settings could be modified within a backup and then restored back to the device to modify app behavior (e.g., change configured remote endpoints) or security settings (e.g., jailbreak detection, certificate pinning, maximum UI login attempts, etc.).

The takeaway: If sensitive data is handled as recommended earlier in this chapter (e.g., stored in the Keychain, with Keychain backed integrity checks, or encrypted with a key that's locked inside the Keychain), backups shouldn't be security issue.

### Process Memory

Analyzing memory can help developers to identify the root causes of problems such as application crashes. However, it can also be used to access to sensitive data. This section describes how to check process' memory for data disclosure.

First, identify the sensitive information that's stored in memory. Sensitive assets are very likely to be loaded into memory at some point. The objective is to make sure that this info is exposed as briefly as possible.

To investigate an application's memory, first create a memory dump. Alternatively, you can analyze the memory in real time with, for example, a debugger. Regardless of the method you use, this is a very error-prone process because dumps provide the data left by executed functions and you might miss executing critical steps. In addition, overlooking data during analysis is quite easy to do unless you know the footprint of the data you're looking for (either its exact value or its format). For example, if the app encrypts according to a randomly generated symmetric key, you're very unlikely to spot the key in memory unless you find its value by other means.

---

Before looking into the source code, checking the documentation and identifying application components provide an overview of where data might be exposed. For example, while sensitive data received from a backend exists in the final model object, multiple copies may also exist in the HTTP client or the XML parser. All these copies should be removed from memory as soon as possible.

Understanding the application's architecture and its interaction with the OS will help you identify sensitive information that doesn't have to be exposed in memory at all. For example, assume your app receives data from one server and transfers it to another without needing any additional processing. That data can be received and handled in encrypted form, which prevents exposure via memory.

However, if sensitive data _does_ need to be exposed via memory, make sure that your app exposes as few copies of this data as possible for as little time as possible. In other words, you want centralized handling of sensitive data, based on primitive and mutable data structures.

Such data structures give developers direct access to memory. Make sure that this access is used to overwrite the sensitive data and cryptographic keys with zeroes. [Apple Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/SecurityDevelopmentChecklists/SecurityDevelopmentChecklists.html "Security Development Checklists") suggests zeroing sensitive data after usage, but provides no recommended ways of doing this.

Examples of preferable data types include `char []` and `int []`, but not `NSString` or `String`. Whenever you try to modify an immutable object, such as a `String`, you actually create a copy and change the copy. Consider using `NSMutableData` for storing secrets on Swift/Objective-C and use [`resetBytes(in:)` method](https://developer.apple.com/documentation/foundation/nsmutabledata/1415526-resetbytes "NSMutableData resetBytes(in:) API reference") for zeroing. Also, see [Clean memory of secret data](https://github.com/veorq/cryptocoding#clean-memory-of-secret-data/ "The Cryptocoding Guidelines by @veorq: Clean memory of secret data") for reference.

Avoid Swift data types other than collections regardless of whether they are considered mutable. Many Swift data types hold their data by value, not by reference. Although this allows modification of the memory allocated to simple types like `char` and `int`, handling a complex type such as `String` by value involves a hidden layer of objects, structures, or primitive arrays whose memory can't be directly accessed or modified. Certain types of usage may seem to create a mutable data object (and even be documented as doing so), but they actually create a mutable identifier (variable) instead of an immutable identifier (constant). For example, many think that the following results in a mutable `String` in Swift, but this is actually an example of a variable whose complex value can be changed (replaced, not modified in place):

```swift
var str1 = "Goodbye"              // "Goodbye", base address:            0x0001039e8dd0
str1.append(" ")                 // "Goodbye ", base address:            0x608000064ae0
str1.append("cruel world!")      // "Goodbye cruel world", base address: 0x6080000338a0
str1.removeAll()                 // "", base address                    0x00010bd66180
```

Notice that the base address of the underlying value changes with each string operation. Here is the problem: To securely erase the sensitive information from memory, we don't want to simply change the value of the variable; we want to change the actual content of the memory allocated for the current value. Swift doesn't offer such a function.

Swift collections (`Array`, `Set`, and `Dictionary`), on the other hand, may be acceptable if they collect primitive data types such as `char` or `int` and are defined as mutable (i.e., as variables instead of constants), in which case they are more or less equivalent to a primitive array (such as `char []`). These collections provide memory management, which can result in unidentified copies of the sensitive data in memory if the collection needs to copy the underlying buffer to a different location to extend it.

Using mutable Objective-C data types, such as `NSMutableString`, may also be acceptable, but these types have the same memory issue as Swift collections. Pay attention when using Objective-C collections; they hold data by reference, and only Objective-C data types are allowed. Therefore, we are looking, not for a mutable collection, but for a collection that references mutable objects.

As we've seen so far, using Swift or Objective-C data types requires a deep understanding of the language implementation. Furthermore, there has been some core re-factoring in between major Swift versions, resulting in many data types' behavior being incompatible with that of other types. To avoid these issues, we recommend using primitive data types whenever data needs to be securely erased from memory.

Unfortunately, few libraries and frameworks are designed to allow sensitive data to be overwritten. Not even Apple considers this issue in the official iOS SDK API. For example, most of the APIs for data transformation (passers, serializes, etc.) operate on non-primitive data types. Similarly, regardless of whether you flag some `UITextField` as _Secure Text Entry_ or not, it always returns data in the form of a `String` or `NSString`.

### IPC

[Inter Process Communication (IPC)](https://nshipster.com/inter-process-communication/ "IPC on iOS") allows processes to send each other messages and data. For processes that need to communicate with each other, there are different ways to implement IPC on iOS:

- **[XPC Services](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html "XPC Services")**: XPC is a structured, asynchronous library that provides basic interprocess communication. It is managed by `launchd`. It is the most secure and flexible implementation of IPC on iOS and should be the preferred method. It runs in the most restricted environment possible: sandboxed with no root privilege escalation and minimal file system access and network access. Two different APIs are used with XPC Services:
  - NSXPCConnection API
  - XPC Services API
- **[Mach Ports](https://developer.apple.com/documentation/foundation/nsmachport "NSMachPort")**: All IPC communication ultimately relies on the Mach Kernel API. Mach Ports allow local communication (intra-device communication) only. They can be implemented either natively or via Core Foundation (CFMachPort) and Foundation (NSMachPort) wrappers.
- **NSFileCoordinator**: The class `NSFileCoordinator` can be used to manage and send data to and from apps via files that are available on the local file system to various processes. [NSFileCoordinator](https://www.atomicbird.com/blog/sharing-with-app-extensions "NSFileCoordinator") methods run synchronously, so your code will be blocked until they stop executing. That's convenient because you don't have to wait for an asynchronous block callback, but it also means that the methods block the running thread.
