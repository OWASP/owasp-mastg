## Data Storage on iOS

The protection of sensitive data, such as authentication tokens and private information, is key for mobile security. In this chapter, you'll learn about the iOS APIs for local data storage, and best practices for using them.

### Testing Local Data Storage

As little sensitive data as possible should be saved in permanent local storage. However, in most practical scenarios, at least some user data must be stored. Fortunately, iOS offers secure storage APIs, which allow developers to use the cryptographic hardware available on every iOS device. If these APIs are used correctly, sensitive data and files can be secured via hardware-backed 256-bit AES encryption.

#### Data Protection API

App developers can leverage the iOS *Data Protection* APIs to implement fine-grained access control for user data stored in flash memory. The APIs are built on top of the Secure Enclave Processor (SEP), which was introduced with the iPhone 5S. The SEP is a coprocessor that provides cryptographic operations for data protection and key management. A device-specific hardware key-the device UID (Unique ID)-is embedded in the secure enclave, ensuring the integrity of data protection even when the operating system kernel is compromised.

The data protection architecture is based on a hierarchy of keys. The UID and the user passcode key (which is derived from the user's passphrase via the PBKDF2 algorithm) sit at the top of this hierarchy. Together, they can be used to "unlock" so-called class keys, which are associated with different device states (e.g., device locked/unlocked).

Every file stored on the iOS file system is encrypted with its own per-file key, which is contained in the file metadata. The metadata is encrypted with the file system key and wrapped with the class key corresponding to the protection class the app selected when creating the file.

![Key Hierarchy iOS](Images/Chapters/0x06d/key_hierarchy_apple.jpg)

*[iOS Data Protection Key Hierarchy](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide")


Files can be assigned to one of four different protection classes, which are explained in more detail in the [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "iOS Security Guide"):

- **Complete Protection (NSFileProtectionComplete)**: A key derived from the user passcode and the device UID protects this class key. The derived key is wiped from memory shortly after the device is locked, making the data inaccessible until the user unlocks the device.

- **Protected Unless Open (NSFileProtectionCompleteUnlessOpen)**: This protection class is similar to Complete Protection, but, if the file is opened when unlocked, the app can continue to access the file even if the user locks the device. This protection class is used when, for example, a mail attachment is downloading in the background.

- **Protected Until First User Authentication (NSFileProtectionCompleteUntilFirstUserAuthentication)**: The file can be accessed as soon as the user unlocks the device for the first time after booting. It can be accessed even if the user subsequently locks the device and the class key is not removed from memory.

- **No Protection (NSFileProtectionNone)**: The key for this protection class is protected with the UID only. The class key is stored in "[Effaceable Storage](https://www.safaribooksonline.com/library/view/hacking-and-securing/9781449325213/ch01s03.html "Effaceable Storage")," which is a region of flash memory on the iOS device that allows the storage of small amounts of data. This protection class exists for fast remote wiping (immediate deletion of the class key, which makes the data inaccessible).

All class keys except `NSFileProtectionNone` are encrypted with a key derived from the device UID and the user's passcode. As a result, decryption can happen only on the device itself and requires the correct passcode.

Since iOS 7, the default data protection class is "Protected Until First User Authentication."

##### The Keychain

The iOS Keychain can be used to securely store short, sensitive bits of data, such as encryption keys and session tokens. It is implemented as an SQLite database that can be accessed through the Keychain APIs only.

On macOS, every user application can create as many Keychains as desired, and every login account has its own Keychain. The [structure of the Keychain on iOS](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html "https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html") is different: only one Keychain is available to all apps. Access to the items can be shared between apps signed by the same developer via the [access groups feature](https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/AddingCapabilities/AddingCapabilities.html "Adding capabilities") of the attribute  [`kSecAttrAccessGroup`](https://developer.apple.com/documentation/security/ksecattraccessgroup "Attribute kSecAttrAccessGroup"). Access to the Keychain is managed by the `securityd` daemon, which grants access according to the app's `Keychain-access-groups`, `application-identifier`, and `application-group` entitlements.

The [Keychain API](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html "Keychain concepts") includes the following main operations:

- `SecItemAdd`
- `SecItemUpdate`
- `SecItemCopyMatching`
- `SecItemDelete`

Data stored in the Keychain is protected via a class structure that is similar to the class structure used for file encryption. Items added to the Keychain are encoded as a binary plist and encrypted with a 128-bit AES per-item key in Galois/Counter Mode (GCM). Note that larger blobs of data aren't meant to be saved directly in the Keychain-that's what the Data Protection API is for. You can configure data protection for Keychain items by setting the `kSecAttrAccessible` key in the call to `SecItemAdd` or `SecItemUpdate`. The following configurable [accessibility values for kSecAttrAccessible](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values#1679100 "Accessibility Values for kSecAttrAccessible") are the Keychain Data Protection classes:

- `kSecAttrAccessibleAlways`: The data in the Keychain item can always be accessed, regardless of whether the device is locked.
- `kSecAttrAccessibleAlwaysThisDeviceOnly`: The data in the Keychain item can always be accessed, regardless of whether the device is locked. The data won't be included in an iCloud or iTunes backup.
- `kSecAttrAccessibleAfterFirstUnlock`: The data in the Keychain item can't be accessed after a restart until the device has been unlocked once by the user.
- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: The data in the Keychain item can't be accessed after a restart until the device has been unlocked once by the user. Items with this attribute do not migrate to a new device. Thus, after restoring from a backup of a different device, these items will not be present.
- `kSecAttrAccessibleWhenUnlocked`: The data in the Keychain item can be accessed only while the device is unlocked by the user.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: The data in the Keychain item can be accessed only while the device is unlocked by the user. The data won't be included in an iCloud or iTunes backup.
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: The data in the Keychain can be accessed only when the device is unlocked. This protection class is only available if a passcode is set on the device. The data won't be included in an iCloud or iTunes backup.


`AccessControlFlags` define the mechanisms with which users can authenticate the key (`SecAccessControlCreateFlags`):
- `kSecAccessControlDevicePasscode`: Access the item via a passcode.
- `kSecAccessControlTouchIDAny`: Access the item via one of the fingerprints registered to TouchID. Adding or removing a fingerprint won't invalidate the item.
- `kSecAccessControlTouchIDCurrentSet`: Access the item via one of the fingerprints registered to TouchID. Adding or removing a fingerprint _will_ invalidate the item.
- `kSecAccessControlUserPresence`: Access the item via either one of the registered fingerprints (using TouchID) or fallback to the passcode.

Please note that keys secured by TouchID (via `kSecAccessControlTouchIDCurrentSet` or `kSecAccessControlTouchIDAny`) are protected by the Secure Enclave: The Keychain holds a token only, not the actual key. The key resides in the Secure Enclave.

Starting with iOS 9, you can do ECC-based signing operations in the Secure Enclave. In that scenario, the private key and the cryptographic operations reside within the Secure Enclave. See the static analysis section for more info on creating the ECC keys.
iOS 9 supports only 256-bit ECC. Furthermore, you need to store the public key in the Keychain because it can't be stored in the Secure Enclave. After the key is created, you can use the `kSecAttrKeyType` to indicate the type of algorithm you want to use the key with.

###### Keychain Data Persistence

On iOS, when an application is uninstalled, the Keychain data used by the application is retained by the device, unlike the data stored by the application sandbox which is wiped. In the event that a user sells their device without performing a factory reset, the buyer of the device may be able to gain access to the previous user's application accounts and data by reinstalling the same applications used by the previous user. This would require no technical ability to perform.

When assessing an iOS application, you should look for Keychain data persistence. This is normally done by using the application to generate sample data that may be stored in the Keychain, uninstalling the application, then reinstalling the application to see whether the data was retained between application installations. You can also verify persistence by using the iOS security assessment framework Needle to read the Keychain. The following Needle commands demonstrate this procedure:

```
python needle.py
[needle] > use storage/data/keychain_dump
[needle] > run
  {
   "Creation Time" : "Jan 15, 2018, 10:20:02 GMT",
   "Account" : "username",
   "Service" : "",
   "Access Group" : "ABCD.com.test.passwordmngr-test",
   "Protection" : "kSecAttrAccessibleWhenUnlocked",
   "Modification Time" : "Jan 15, 2018, 10:28:02 GMT",
   "Data" : "testUser",
   "AccessControl" : "Not Applicable"
 },
 {
   "Creation Time" : "Jan 15, 2018, 10:20:02 GMT",
   "Account" : "password",
   "Service" : "",
   "Access Group" : "ABCD.com.test.passwordmngr-test,
   "Protection" : "kSecAttrAccessibleWhenUnlocked",
   "Modification Time" : "Jan 15, 2018, 10:28:02 GMT",
   "Data" : "rosebud",
   "AccessControl" : "Not Applicable"
 }
```

There's no iOS API that developers can use to force wipe data when an application is uninstalled. Instead, developers should take the following steps to prevent Keychain data from persisting between application installations:
* When an application is first launched after installation, wipe all Keychain data associated with the application. This will prevent a device's second user from accidentally gaining access to the previous user's accounts. The following Swift example is a basic demonstration of this wiping procedure:

```swift
let userDefaults = UserDefaults.standard

if userDefaults.bool(forKey: "hasRunBefore") == false {
     // Remove Keychain items here

     // Update the flag indicator
     userDefaults.set(true, forKey: "hasRunBefore")
     userDefaults.synchronize() // Forces the app to update UserDefaults
}
```

* When developing logout functionality for an iOS application, make sure that the Keychain data is wiped as part of account logout. This will allow users to clear their accounts before uninstalling an application.

#### Static Analysis

When you have access to the source code of an iOS app, try to spot sensitive data that's saved and processed throughout the app. This includes passwords, secret keys, and personally identifiable information (PII), but it may as well include other data identified as sensitive by industry regulations, laws, and company policies. Look for this data being saved via any of the local storage APIs listed below. Make sure that sensitive data is never stored without appropriate protection. For example, authentication tokens should not be saved in `NSUserDefaults` without additional encryption.

The encryption must be implemented so that the secret key is stored in the Keychain with secure settings, ideally `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. This ensures the usage of hardware-backed storage mechanisms. Make sure that the `AccessControlFlags` are set according to the security policy of the keys in the KeyChain.

[Generic examples of using the KeyChain](https://developer.apple.com/library/content/samplecode/GenericKeychain/Introduction/Intro.html#//apple_ref/doc/uid/DTS40007797-Intro-DontLinkElementID_2 "GenericKeyChain") to store, update, and delete data can be found in the official Apple documentation. The official Apple documentation also includes an example of using [TouchID and passcode protected keys](https://developer.apple.com/library/content/samplecode/KeychainTouchID/Listings/KeychainTouchID_AAPLLocalAuthenticationTestsViewController_m.html#//apple_ref/doc/uid/TP40014530-KeychainTouchID_AAPLLocalAuthenticationTestsViewController_m-DontLinkElementID_10 "KeychainTouchID").

Here is sample Swift code you can use to create keys (Notice the `kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave`: this indicates that we want to use the Secure Enclave directly.):

```swift
 // private key parameters
    let privateKeyParams: [String: AnyObject] = [
        kSecAttrLabel as String: "privateLabel",
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: "applicationTag"
    ]        
    // public key parameters
    let publicKeyParams: [String: AnyObject] = [
        kSecAttrLabel as String: "publicLabel",
        kSecAttrIsPermanent as String: false,
        kSecAttrApplicationTag as String: "applicationTag"
    ]

    // global parameters
    let parameters: [String: AnyObject] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeEC,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPublicKeyAttrs as String: publicKeyParams,
        kSecPrivateKeyAttrs as String: privateKeyParams
    ]        

    var pubKey, privKey: SecKeyRef?
    let status = SecKeyGeneratePair(parameters, &pubKey, &privKey)

```

When checking an iOS app for insecure data storage, consider the following ways to store data because none of them encrypt data by default:

##### `NSUserDefaults`

The [`NSUserDefaults`](https://developer.apple.com/documentation/foundation/nsuserdefaults "NSUserDefaults Class") class provides a programmatic interface for interacting with the default system. The default system allows an application to customize its behavior according to user  preferences. Data saved by `NSUserDefaults` can be viewed in the application bundle. This class stores data in a plist file, but it's meant to be used with small amounts of data.

##### File system

- `NSData`: creates static data objects, while `NSMutableData` creates dynamic data objects. `NSData` and `NSMutableData` are typically used for data storage, but they are also useful for distributed objects applications, in which data contained in data objects can be copied or moved between applications. The following are methods used to write `NSData` objects:
   - `NSDataWritingWithoutOverwriting`
   - `NSDataWritingFileProtectionNone`
   - `NSDataWritingFileProtectionComplete`
   - `NSDataWritingFileProtectionCompleteUnlessOpen`
   - `NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication`
- `writeToFile`: stores data as part of the `NSData` class
- `NSSearchPathForDirectoriesInDomains, NSTemporaryDirectory`: used to manage file paths
- `NSFileManager`: lets you examine and change the contents of the file system. You can use `createFileAtPath` to create a file and write to it.

The following example shows how to create a securely encrypted file using the `createFileAtPath` method:

```objective-c
[[NSFileManager defaultManager] createFileAtPath:[self filePath]
  contents:[@"secret text" dataUsingEncoding:NSUTF8StringEncoding]
  attributes:[NSDictionary dictionaryWithObject:NSFileProtectionComplete
  forKey:NSFileProtectionKey]];
```

##### CoreData

[`Core Data`](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/CoreData/nsfetchedresultscontroller.html#//apple_ref/doc/uid/TP40001075-CH8-SW1 "Core Data iOS") is a framework for managing the model layer of objects in your application. It provides general and automated solutions to common tasks associated with object life cycles and object graph management, including persistence. [Core Data can use SQLite as its persistent store](https://cocoacasts.com/what-is-the-difference-between-core-data-and-sqlite/ "What Is the Difference Between Core Data and SQLite"), but the framework itself is not a database.

##### SQLite Databases

The SQLite 3 library must be added to an app if the app is to use SQLite. This library is a C++ wrapper that provides an API for the SQLite commands.

##### Realm databases

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

##### Couchbase Lite Databases

[Couchbase Lite](https://github.com/couchbase/couchbase-lite-ios "Couchbase Lite") is a lightweight, embedded, document-oriented (NoSQL)  database engine that can be synced. It compiles natively for iOS and Mac OS.

##### YapDatabase

[YapDatabase](https://github.com/yapstudios/YapDatabase "YapDatabase") is a key/value store built on top of SQLite.

#### Dynamic Analysis

One way to determine whether sensitive information (like credentials and keys) is stored insecurely without leveraging native iOS functions is to analyze the app's data directory. Triggering all app functionality before the data is analyzed is important because the app may store sensitive data only after specific functionality has been triggered. You can then perform static analysis for the data dump according to generic keywords and app-specific data.

The following steps can be used to determine how the application stores data locally on a jailbroken iOS device:

1. Trigger the functionality that stores potentially sensitive data.
2. Connect to the iOS device and navigate to the following directory (this applies to iOS versions 8.0 and above): `/var/mobile/Containers/Data/Application/$APP_ID/`
3. Execute grep with the data that you've stored, for example: `grep -iRn "USERID"`.
4. If the sensitive data is stored in plaintext, the app fails this test.

You can analyze the app's data directory on a non-jailbroken iOS device by using third-party applications, such as [iMazing](https://imazing.com "iMazing").

1. Trigger the functionality that stores potentially sensitive data.
2. Connect the iOS device to your workstation and launch iMazing.
3. Select "Apps," right-click the desired iOS application, and select "Extract App."
4. Navigate to the output directory and locate $APP_NAME.imazing. Rename it `$APP_NAME.zip`.
5. Unpack the zip file. You can then analyze the application data.

> Note that tools like iMazing don't copy data directly from the device. They try to extract data from the backups they create. Therefore, getting all the app data that's stored on the iOS device is impossible: not all folders are included in backups. Use a jailbroken device or repackage the app with Frida and use a tool like objection to access all the data and files.

If you added the Frida library to the app and repackaged it as described in "Dynamic Analysis on Non-Jailbroken Devices" (from the "Basic Security Testing" chapter), you can use [objection](https://github.com/sensepost/objection "objection") to transfer files directly from the app's data directory or [read files in objection](https://github.com/sensepost/objection/wiki/Using-objection#getting-started-ios-edition "Getting started iOS edition").

Important file system locations are:

- `AppName.app`
  - This app's bundle contains the app and all its resources.
  - This directory is visible to users, but users can't write to it.
  - Content in this directory is not backed up.
- Documents/
  - Use this directory to store user-generated content.
  - Visible to users and users can write to it.
  - Content in this directory is backed up.
  - The app can disable paths by setting `NSURLIsExcludedFromBackupKey`.
- Library/
  - This is the top-level directory for all files that aren't user data files.
  - iOS apps usually use the `Application Support` and `Caches` subdirectories, but you can create custom subdirectories.
- Library/Caches/
  - Contains semi-persistent cached files.
  - Invisible to users and users can't write to it.
  - Content in this directory is not backed up.
  - The OS may delete this directory's files automatically when the app is not running and storage space is running low.
- Library/Application Support/
  - Contains persistent files necessary for running the app.
  - Invisible to users and users can't write to it.
  - Content in this directory is backed up.
  - The app can disable paths by setting `NSURLIsExcludedFromBackupKey`
- Library/Preferences/
  - Used for storing properties, objects that can persist even after an application is restarted.
  - Information is saved, unencrypted, inside the application sandbox in a plist file called [BUNDLE_ID].plist.
  - All the key/value pairs stored using `NSUserDefaults` can be found in this file.
- tmp/
  - Use this directory to write temporary files that need not persist between app launches.
  - Contains non-persistent cached files.
  - Invisible to users.
  - Content in this directory is not backed up.
  - The OS may delete this directory's files automatically when the app is not running and storage space is running low.

The Keychain contents can be dumped during dynamic analysis. On a jailbroken device, you can use [Keychain dumper](https://github.com/ptoomey3/Keychain-Dumper/ "Keychain Dumper") as described in the chapter "Basic Security Testing on iOS."

The path to the Keychain file is
```
/private/var/Keychains/keychain-2.db
```

On a non-jailbroken device, you can use objection to [dump the Keychain items](https://github.com/sensepost/objection/wiki/Notes-About-The-Keychain-Dumper "Notes About The Keychain Dumper") created and stored by the app.

##### Dynamic Analysis with Needle

On a jailbroken device, you can use the iOS security assessment framework Needle to find vulnerabilities caused by the application's data storage mechanism.

**Reading the Keychain**

To use Needle to read the Keychain, execute the following command:

```
[needle] > use storage/data/keychain_dump
[needle][keychain_dump] > run
```  

**Searching for Binary Cookies**

iOS applications often store binary cookie files in the application sandbox. Cookies are binary files containing cookie data for application WebViews. You can use Needle to convert these files to a readable format and inspect the data. Use the following Needle module, which searches for binary cookie files stored in the application container, lists their data protection values, and gives the user the options to inspect or download the file:

```
[needle] > use storage/data/files_binarycookies
[needle][files_binarycookies] > run
```

**Searching for Property List Files**

iOS applications often store data in property list (plist) files that are stored in both the application sandbox and the IPA package. Sometimes these files contain sensitive information, such as usernames and passwords; therefore, the contents of these files should be inspected during iOS assessments. Use the following Needle module, which searches for plist files stored in the application container, lists their data protection values, and gives the user the options to inspect or download the file:

```
[needle] > use storage/data/files_plist
[needle][files_plist] > run
```

**Searching for Cache Databases**

iOS applications can store data in cache databases. These databases contain data such as web requests and responses. Sometimes the data is sensitive. Use the following Needle module, which searches for cache files stored in the application container, lists their data protection values, and gives the user the options to inspect or download the file:

```
[needle] > use storage/data/files_cachedb
[needle][files_cachedb] > run
```

**Searching for SQLite Databases**

iOS applications typically use SQLite databases to store data required by the application. Testers should check the data protection values of these files and their contents for sensitive data. Use the following Needle module, which searches for SQLite databases stored in the application container, lists their data protection values, and gives the user the options to inspect or download the file:

```
[needle] > use storage/data/files_sql
[needle][files_sql] >
```

### Checking Logs for Sensitive Data

There are many legitimate reasons for creating log files on a mobile device, including keeping track of crashes or errors that are stored locally while the device is offline (so that they can be sent to the app's developer once online), and storing usage statistics. However, logging sensitive data, such as credit card numbers and session information, may expose the data to attackers or malicious applications.
Log files can be created in several ways. The following list shows the methods available on iOS:

- NSLog Method
- printf-like function
- NSAssert-like function
- Macro

#### Static Analysis

Use the following keywords to check the app's source code for predefined and custom logging statements:

- For predefined and built-in functions:
  - NSLog
  - NSAssert
  - NSCAssert
  - fprintf
- For custom functions:
  - Logging
  - Logfile

A generalized approach to this issue is to use a define to enable `NSLog` statements for development and debugging, then disable them before shipping the software. You can do this by adding the following code to the appropriate PREFIX_HEADER (\*.pch) file:

```C#
#ifdef DEBUG
#   define NSLog (...) NSLog(__VA_ARGS__)
#else
#   define NSLog (...)
#endif
```

#### Dynamic Analysis

Navigate to a screen that displays input fields that take sensitive user information. Two methods apply to checking log files for sensitive data:

1. Connect to the iOS device and execute the following command:
```
tail -f /var/log/syslog
```

2. Connect your iOS device via USB and launch Xcode. Navigate to Window > Devices and Simulators, select your device and then the Open Console option (as of Xcode 9).

After starting either method one or two, fill in the input fields. If sensitive data is displayed in the output, the app fails this test.

To capture the logs of an iOS application, you can monitor log files with Needle:

```
[needle] > use dynamic/monitor/syslog
[needle][syslog] > run
```

### Determining Whether Sensitive Data Is Sent to Third Parties

Various third-party services can be embedded in the app. The features these services provide can involve tracking services to monitor the user's behavior while using the app, selling banner advertisements, or improving the user experience.
The downside to third-party services is that developers don't know the details of the code executed via third-party libraries. Consequently, no more information than is necessary should be sent to a service, and no sensitive information should be disclosed.

The downside is that a developer doesn’t know in detail what code is executed via 3rd party libraries and therefore giving up visibility. Consequently it should be ensured that not more than the information needed is sent to the service and that no sensitive information is disclosed.

Most third-party services are implemented in two ways:
- with a standalone library
- with a full SDK

#### Static Analysis

To determine whether API calls and functions provided by the third-party library are used according to best practices, review their source code.

All data that's sent to third-party services should be anonymized to prevent exposure of PII (Personal Identifiable Information) that would allow the third party to identify the user account. No other data (such as IDs that can be mapped to a user account or session) should be sent to a third party.

#### Dynamic Analysis

All requests made to external services should be analyzed for embedded sensitive information. By using an interception proxy, you can investigate the traffic between the app and the third party's endpoints. When the app is in use, all requests that don't go directly to the server that hosts the main function should be checked for sensitive information that's sent to a third party. This information could be PII in a request to a tracking or ad service.

### Finding Sensitive Data in the Keyboard Cache

Several options for simplifying keyboard input are available to users. These options include autocorrection and spell checking. Most keyboard input is cached by default, in `/private/var/mobile/Library/Keyboard/dynamic-text.dat`.

The [UITextInputTraits protocol](https://developer.apple.com/reference/uikit/uitextinputtraits "UITextInputTraits protocol") is used for keyboard caching. The UITextField, UITextView, and UISearchBar classes automatically support this protocol and it offers the following properties:

- `var autocorrectionType: UITextAutocorrectionType` determines whether autocorrection is enabled during typing. When autocorrection is enabled, the text object tracks unknown words and suggests suitable replacements, replacing the typed text automatically unless the user overrides the replacement. The default value of this property is `UITextAutocorrectionTypeDefault`, which for most input methods enables autocorrection.
- `var secureTextEntry: BOOL` determines whether text copying and text caching are disabled and hides the text being entered for `UITextField`. The default value of this property is "NO."

#### Static Analysis

- Search through the source code for similar implementations, such as

```ObjC
  textObject.autocorrectionType = UITextAutocorrectionTypeNo;
  textObject.secureTextEntry = YES;
```

- Open xib and storyboard files in the `Interface Builder` of Xcode and verify the states of `Secure Text Entry` and `Correction` in the `Attributes Inspector` for the appropriate object.

The application must prevent the caching of sensitive information entered into text fields. You can prevent caching by disabling it programmatically, using the `textObject.autocorrectionType = UITextAutocorrectionTypeNo` directive in the desired UITextFields, UITextViews, and UISearchBars. For data that should be masked, such as PINs and passwords, set `textObject.secureTextEntry` to "YES."

```ObjC
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

#### Dynamic Analysis

If a jailbroken iPhone is available, execute the following steps:

1. Reset your iOS device keyboard cache by navigating to Settings > General > Reset > Reset Keyboard Dictionary.
2. Use the application and identify the functionalities that allow users to enter sensitive data.
3. Dump the keyboard cache file `dynamic-text.dat` into the following directory (which might be different for iOS versions before 8.0):
`/private/var/mobile/Library/Keyboard/`
4. Look for sensitive data, such as username, passwords, email addresses, and credit card numbers. If the sensitive data can be obtained via the keyboard cache file, the app fails this test.

```objective-c
UITextField *textField = [ [ UITextField alloc ] initWithFrame: frame ];
textField.autocorrectionType = UITextAutocorrectionTypeNo;
```

If you must use a non-jailbroken iPhone:
1. Reset the keyboard cache.
2. Key in all sensitive data.
3. Use the app again and determine whether autocorrect suggests previously entered sensitive information.


### Checking the Clipboard for Sensitive Data

#### Overview

When typing data into input fields, the clipboard can be used to copy in data. The clipboard is accessible system-wide and is therefore shared by apps. This sharing can be misused by malicious apps to get sensitive data that has been stored in the clipboard.

Before iOS 9, a malicious app might monitor the pasteboard in the background while periodically retrieving `[UIPasteboard generalPasteboard].string`. As of iOS 9, pasteboard content is accessible to apps in the foreground only.

#### Static Analysis

Search the source code for subclasses of `UITextField`.

```#ObjC
@interface name_of_sub_class : UITextField
action == @select(cut:)
action == @select(copy:)
```

One way to [disable the clipboard on iOS](http://stackoverflow.com/questions/1426731/how-disable-copy-cut-select-select-all-in-uitextview "Disable clipboard in iOS") is demonstrated below:

```ObjC
@interface NoSelectTextField : UITextField

@end

@implementation NoSelectTextField

- (BOOL)canPerformAction:(SEL)action withSender:(id)sender {
    if (action == @selector(paste:) ||
        action == @selector(cut:) ||
        action == @selector(copy:) ||
        action == @selector(select:) ||
        action == @selector(selectAll:) ||
        action == @selector(delete:) ||
        action == @selector(makeTextWritingDirectionLeftToRight:) ||
        action == @selector(makeTextWritingDirectionRightToLeft:) ||
        action == @selector(toggleBoldface:) ||
        action == @selector(toggleItalics:) ||
        action == @selector(toggleUnderline:)
        ) {
            return NO;
    }
    return [super canPerformAction:action withSender:sender];
}

@end
```

To clear the pasteboard with [UIPasteboardNameGeneral](https://developer.apple.com/reference/uikit/uipasteboardnamegeneral?language=objc "UIPasteboardNameGeneral"), use the following code snippet:

```ObjC
UIPasteboard *pb = [UIPasteboard generalPasteboard];
[pb setValue:@"" forPasteboardType:UIPasteboardNameGeneral];
```

#### Dynamic Analysis

Navigate to a screen in the app that has input fields that take sensitive information, such as a username, password, or credit card number. Enter a value and double tap on the input field. If the "Select," "Select All," and "Paste" options show up, tap on "Select" or "Select All"; you should be allowed to "Cut," "Copy," "Paste," or "Define." The "Cut" and "Copy" options should be disabled for sensitive input fields; otherwise, someone could retrieve the input value by pasting it. If the sensitive input fields allow you to "Cut" or "Copy" the values, the app fails this test.

You can use Needle to check for sensitive data written to the clipboard on jailbroken devices. Launch the following Needle module to start passively monitoring the clipboard (all clipboard data will be written to the specified output file):

```
[needle] > use dynamic/monitor/pasteboard
[needle] > set OUTPUT "./clipboard-logs.txt"
[needle] > run
 ```

### Determining Whether Sensitive Data Is Exposed via IPC Mechanisms

#### Overview

[Inter Process Communication (IPC)](http://nshipster.com/inter-process-communication/ "IPC on iOS") allows processes to send each other messages and data. For processes that need to communicate with each other, there are different ways to implement IPC on iOS:

- **[XPC Services](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html "XPC Services")**: XPC is a structured, asynchronous library that provides basic interprocess communication. It is managed by `launchd`. It is the most secure and flexible implementation of IPC on iOS and should be the preferred method. It runs in the most restricted environment possible: sandboxed with no root privilege escalation and minimal file system access and network access. Two different APIs are used with XPC Services:
  * NSXPCConnection API
  * XPC Services API
- **[Mach Ports](https://developer.apple.com/documentation/foundation/nsmachport "NSMachPort")**: All IPC communication ultimately relies on the Mach Kernel API. Mach Ports allow local communication (intra-device communication) only. They can be implemented either natively or via Core Foundation (CFMachPort) and Foundation (NSMachPort) wrappers.
- **NSFileCoordinator**: The class `NSFileCoordinator` can be used to manage and send data to and from apps via files that are available on the local file system to various processes. [NSFileCoordinator](http://www.atomicbird.com/blog/sharing-with-app-extensions "NSFileCoordinator") methods run synchronously, so your code will be blocked until they stop executing. That's convenient because you don't have to wait for an asynchronous block callback, but it also means that the methods block the running thread.

#### Static Analysis

The following section summarizes keywords that you should look for to identify IPC implementations within iOS source code.

##### XPC Services

Several classes may be to implement the NSXPCConnection API:

- NSXPCConnection
- NSXPCInterface
- NSXPCListener
- NSXPCListenerEndpoint

You can set [security attributes](https://www.objc.io/issues/14-mac/xpc/#security-attributes-of-the-connection "Security Attributes of NSXPCConnection") for the connection. The attributes should be verified.

Check for the following two files in the Xcode project for the XPC Services API (which is C-based):

- [`xpc.h`](https://developer.apple.com/documentation/xpc/xpc_services_xpc.h "xpc.h")
- `connection.h`

##### Mach Ports

Keywords to look for in low-level implementations:
- mach\_port\_t
- mach\_msg\_*

Keywords to look for in high-level implementations (Core Foundation and Foundation wrappers):
- CFMachPort
- CFMessagePort
- NSMachPort
- NSMessagePort

##### NSFileCoordinator

Keywords to look for:
- NSFileCoordinator

#### Dynamic Analysis

Verify IPC mechanisms with static analysis of the iOS source code. No iOS tool is currently available  to verify IPC usage.


### Checking for Sensitive Data Disclosed Through the User Interface

#### Overview

Entering sensitive information when, for example, registering an account or making payments, is an essential part of using many apps. This data may be financial information such as credit card data or user account passwords. The data may be exposed if the app doesn't properly mask it while it is being typed.

Masking sensitive data (by showing asterisks or dots instead of clear text) should be enforced.

#### Static Analysis

A text field that masks its input can be configured in two ways:

**Storyboard**
In the iOS project's storyboard, navigate to the configuration options for the text field that takes sensitive data. Make sure that the option "Secure Text Entry" is selected. If this option is activated, dots are shown in the text field in place of the text input.

**Source Code**
If the text field is defined in the source code, make sure that the option [isSecureTextEntry](https://developer.apple.com/documentation/uikit/uitextinputtraits/1624427-issecuretextentry "isSecureTextEntry in Text Field") is set to "true." This option obscures the text input by showing dots.

```
sensitiveTextField.isSecureTextEntry = true
```

#### Dynamic Analysis

To determine whether the application leaks any sensitive information to the user interface, run the application and identify components that either show such information or take it as input.

If the information is masked by, for example, asterisks or dots, the app isn't leaking data to the user interface.

### Testing Backups for Sensitive Data

#### Overview

iOS includes auto-backup features that create copies of the data stored on the device. On iOS, backups can be made through iTunes or the cloud (via the iCloud backup feature). In both cases, the backup includes nearly all data stored on the device except highly sensitive data such as Apple Pay information and TouchID settings.

Since iOS backs up installed apps and their data, an obvious concern is whether sensitive user data stored by the app might accidentally leak through the backup. The answer to this question is "yes"-but only if the app insecurely stores sensitive data in the first place.

##### How the Keychain Is Backed Up

When users back up their iOS device, the Keychain data is backed up as well, but the secrets in the Keychain remain encrypted. The class keys necessary to decrypt the Keychain data aren't included in the backup. Restoring the Keychain data requires restoring the backup to a device and unlocking the device with the users passcode.

Keychain items for which the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` attribute is set can be decrypted only if the backup is restored to the backed up device. Someone trying to extract this Keychain data from the backup couldn't decrypt it without access to the crypto hardware inside the originating device.

The takeaway: If sensitive data is handled as recommended earlier in this chapter (stored in the Keychain or encrypted with a key that's locked inside the Keychain), backups aren't a security issue.

##### Static Analysis

An iTunes backup of a device on which a mobile application has been installed will include all subdirectories (except for `Library/Caches/`) and files in the [app's private directory](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12 "Directories of an iOS App").

Therefore, avoid storing sensitive data in plaintext within any of the files or folders that are in the app's private directory or subdirectories.

Although all the files in `Documents/` and `Library/Application Support/` are always backed up by default, you can [exclude files from the backup](https://developer.apple.com/library/content/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28 "Where You Should Put Your App's Files") by calling `NSURL setResourceValue:forKey:error:` with the `NSURLIsExcludedFromBackupKey` key.

You can use the [NSURLIsExcludedFromBackupKey](https://developer.apple.com/reference/foundation/nsurl#//apple_ref/c/data/NSURLIsExcludedFromBackupKey "NSURLIsExcludedFromBackupKey") and [CFURLIsExcludedFromBackupKey](https://developer.apple.com/reference/corefoundation/cfurl-rd7#//apple_ref/c/data/kCFURLIsExcludedFromBackupKey "kCFURLIsExcludedFromBackupKey") file system properties to exclude files and directories from backups. An app that needs to exclude many files can do so by creating its own subdirectory and marking that directory excluded. Apps should create their own directories for exclusion instead of excluding system-defined directories.

Both file system properties are preferable to the deprecated approach of directly setting an extended attribute. All apps running on iOS version 5.1 and later should use these properties to exclude data from backups.

The following is [sample Objective-C code for excluding a file from a backup](https://developer.apple.com/library/content/qa/qa1719/index.html "How do I prevent files from being backed up to iCloud and iTunes?") on iOS 5.1 and later:

```#ObjC
- (BOOL)addSkipBackupAttributeToItemAtPath:(NSString *) filePathString
{
    NSURL* URL= [NSURL fileURLWithPath: filePathString];
    assert([[NSFileManager defaultManager] fileExistsAtPath: [URL path]]);

    NSError *error = nil;
    BOOL success = [URL setResourceValue: [NSNumber numberWithBool: YES]
                                  forKey: NSURLIsExcludedFromBackupKey error: &error];
    if(!success){
        NSLog(@"Error excluding %@ from backup %@", [URL lastPathComponent], error);
    }
    return success;
}
```

The following is [sample Swift code for excluding a file from a backup](https://developer.apple.com/library/content/qa/qa1719/index.html "How do I prevent files from being backed up to iCloud and iTunes?") on iOS 5.1 and later:

```
 func addSkipBackupAttributeToItemAtURL(filePath:String) -> Bool
    {
        let URL:NSURL = NSURL.fileURLWithPath(filePath)

        assert(NSFileManager.defaultManager().fileExistsAtPath(filePath), "File \(filePath) doesn't exist")

        var success: Bool
        do {
            try URL.setResourceValue(true, forKey:NSURLIsExcludedFromBackupKey)
            success = true
        } catch let error as NSError {
            success = false
            print("Error excluding \(URL.lastPathComponent) from backup \(error)");
        }

        return success
    }
```


#### Dynamic Analysis

After the app data has been backed up, review the data that's in the backed up files and folders. The following directories should be reviewed for sensitive data:

- Documents/
- Library/Application Support/
- Library/Preferences/

Refer to the overview of this section for more on the purpose of each of these directories.

### Testing Auto-Generated Screenshots for Sensitive Information

#### Overview

Manufacturers want to provide device users with an aesthetically pleasing effect when an application is started or exited, so they introduced the concept of saving a screenshot when the application goes into the background. This feature can pose a security risk because screenshots (which may display sensitive information such as an email or corporate documents) are written to local storage, where they can be recovered by a rogue application with a sandbox bypass exploit or someone who steals the device.

#### Static Analysis

While analyzing the source code, look for the fields or screens that take or display sensitive data. Use [UIImageView](https://developer.apple.com/documentation/uikit/uiimageview "UIImageView") to determine whether the application sanitizes the screen before being backgrounded.

The following is a sample remediation method that will set a default screenshot:

```
@property (UIImageView *)backgroundImage;

- (void)applicationDidEnterBackground:(UIApplication *)application {
    UIImageView *myBanner = [[UIImageView alloc] initWithImage:@"overlayImage.png"];
    self.backgroundImage = myBanner;
    [self.window addSubview:myBanner];
}
```

This sets the background image to `overlayImage.png` whenever the application is backgrounded. It prevents sensitive data leaks because `overlayImage.png` will always override the current view.

#### Dynamic Analysis

Navigate to an application screen that displays sensitive information, such as a username, an email address, or account details. Background the application by hitting the Home button on your iOS device. Connect to the iOS device and navigate to the following directory (which may be different for iOS versions below 8.0):

`/var/mobile/Containers/Data/Application/$APP_ID/Library/Caches/Snapshots/`

Screenshot caching vulnerabilities can also be detected with Needle. This is demonstrated in the following Needle excerpt:

```
[needle] > use storage/caching/screenshot
[needle][screenshot] > run
[V] Creating timestamp file...
[*] Launching the app...
[*] Background the app by hitting the home button, then press enter:

[*] Checking for new screenshots...
[+] Screenshots found:
[+]   /private/var/mobile/Containers/Data/Application/APP_ID/Library/Caches/Snapshots/app_name/B75DD942-76D1-4B86-8466-B79F7A78B437@2x.png
[+]   /private/var/mobile/Containers/Data/Application/APP_ID/Library/Caches/Snapshots/app_name/downscaled/12B93BCB-610B-44DA-A171-AF205BA71269@2x.png
[+] Retrieving screenshots and saving them in: /home/user/.needle/output
```

If the application caches the sensitive information in a screenshot, the app fails this test.

You should have a default screenshot to be cached whenever the application enters the background.

### Testing Memory for Sensitive Data

#### Overview

Analyzing memory can help developers to identify the root causes of problems such as application crashes. However, it can also be used to access to sensitive data. This section describes how to check process' memory for data disclosure.

First, identify the sensitive information that's stored in memory. Sensitive assets are very likely to be loaded into memory at some point. The objective is to make sure that this info is exposed as briefly as possible.

To investigate an application's memory, first create a memory dump. Alternatively, you can analyze the memory in real time with, for example, a debugger. Regardless of the method you use, this is a very error-prone process because dumps provide the data left by executed functions and you might miss executing critical steps. In addition, overlooking data during analysis is quite easy to do unless you know the footprint of the data you're looking for (either its exact value or its format). For example, if the app encrypts according to a randomly generated symmetric key, you're very unlikely to spot the key in memory unless you find its value by other means.

Therefore, you're better off starting with static analysis.

#### Static Analysis

Before looking into the source code, checking the documentation and identifying application components provide an overview of where data might be exposed. For example, while sensitive data received from a backend exists in the final model object, multiple copies may also exist in the HTTP client or the XML parser. All these copies should be removed from memory as soon as possible.

Understanding the application's architecture and its interaction with the OS will help you identify sensitive information that doesn't have to be exposed in memory at all. For example, assume your app receives data from one server and transfers it to another without needing any additional processing. That data can be received and handled in encrypted form, which prevents exposure via memory.

However, if sensitive data _does_ need to be exposed via memory, make sure that your app exposes as few copies of this data as possible for as little time as possible. In other words, you want centralized handling of sensitive data, based on primitive and mutable data structures.

Such data structures give developers direct access to memory. Make sure that this access is used to overwrite the sensitive data with dummy data (which is typically zeroes). Examples of preferable data types include `char []` and `int []`, but not `NSString` or `String`. Whenever you try to modify an immutable object, such as a `String`, you actually create a copy and change the copy.

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

In summary, when performing static analysis for sensitive data exposed via memory, you should
- try to identify application components and map where the data is used,
- make sure that sensitive data is handled with as few components as possible,
- make sure that object references are properly removed once the object containing sensitive data is no longer needed,
- make sure that highly sensitive data is overwritten as soon as it is no longer needed,
- not pass such data via immutable data types, such as `String` and `NSString`,
- avoid non-primitive data types (because they might leave data behind),
- overwrite the value in memory before removing references,
- pay attention to third-party components (libraries and frameworks). Having a public API that handles data according to the recommendations above is a good indicator that developers considered the issues discussed here.

#### Dynamic Analysis

Several approaches and tools are available for dumping an iOS app's memory.

On a non-jailbroken device, you can dump the app's process memory with [objection](https://github.com/sensepost/objection "Objection") and [Fridump](https://github.com/Nightbringer21/fridump "Fridump"). To take advantage of these tools, the iOS app must be repackaged with `FridaGadget.dylib` and re-signed. A detailed explanation of this process is in the section "Dynamic Analysis on Non-Jailbroken Devices," in the chapter "Basic Security Testing."

##### Objection (No Jailbreak needed)

With objection it is possible to dump all memory of the running process on the device.


```
(virtual-python3) ➜ objection explore

     _     _         _   _
 ___| |_  |_|___ ___| |_|_|___ ___
| . | . | | | -_|  _|  _| | . |   |
|___|___|_| |___|___|_| |_|___|_|_|
        |___|(object)inject(ion) v0.1.0

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
iPhone on (iPhone: 10.3.1) [usb] # memory dump all /Users/foo/memory_iOS/memory
Dumping 768.0 KiB from base: 0x1ad200000  [####################################]  100%
Memory dumped to file: /Users/foo/memory_iOS/memory
```

After the memory has been dumped, executing the command `strings` with the dump as argument will extract the strings.

```
$ strings memory > strings.txt
```

Open `strings.txt` in your favorite editor and dig through it to identify sensitive information.

You can also display the current process' loaded modules.

```
iPhone on (iPhone: 10.3.1) [usb] # memory list modules
Name                              Base         Size                 Path
--------------------------------  -----------  -------------------  ---------------------------------------------------------------------------------
foobar                            0x1000d0000  11010048 (10.5 MiB)  /var/containers/Bundle/Application/D1FDA1C6-D161-44D0-BA5D-60F73BB18B75/...
FridaGadget.dylib                 0x100ec8000  3883008 (3.7 MiB)    /var/containers/Bundle/Application/D1FDA1C6-D161-44D0-BA5D-60F73BB18B75/...
libsqlite3.dylib                  0x187290000  1118208 (1.1 MiB)    /usr/lib/libsqlite3.dylib
libSystem.B.dylib                 0x18577c000  8192 (8.0 KiB)       /usr/lib/libSystem.B.dylib
libcache.dylib                    0x185bd2000  20480 (20.0 KiB)     /usr/lib/system/libcache.dylib
libsystem_pthread.dylib           0x185e5a000  40960 (40.0 KiB)     /usr/lib/system/libsystem_pthread.dylib
libsystem_kernel.dylib            0x185d76000  151552 (148.0 KiB)   /usr/lib/system/libsystem_kernel.dylib
libsystem_platform.dylib          0x185e53000  28672 (28.0 KiB)     /usr/lib/system/libsystem_platform.dylib
libdyld.dylib                     0x185c81000  20480 (20.0 KiB)     /usr/lib/system/libdyld.dylib
```


##### Fridump (No Jailbreak needed)

The original version of Fridump is no longer maintained, and the tool works only with Python 2. The latest Python version (3.x) should be used for Frida, so Fridump doesn't work out of the box.

If you're getting the following error message despite your iOS device being connected via USB, checkout [Fridump with the fix for Python 3](https://github.com/sushi2k/fridump "Fridump for Python3").

```
➜  fridump_orig git:(master) ✗ python fridump.py -u Gadget

        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|

Can't connect to App. Have you connected the device?
```

Once Fridump is working, you need the name of the app you want to dump, which you can get with `frida-ps`. Afterwards, specify the app name in Fridump.

```
➜  fridump git:(master) ✗ frida-ps -U
 PID  Name
----  ------
1026  Gadget

➜  fridump git:(master) python3 fridump.py -u Gadget -s

        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|

Current Directory: /Users/foo/PentestTools/iOS/fridump
Output directory is set to: /Users/foo/PentestTools/iOS/fridump/dump
Creating directory...
Starting Memory dump...
Progress: [##################################################] 100.0% Complete

Running strings on all files:
Progress: [##################################################] 100.0% Complete

Finished! Press Ctrl+C
```

When you add the `-s` flag, all strings are extracted from the dumped raw memory files and added to the file `strings.txt`, which is stored in Fridump's dump directory.


### References

- [Demystifying the Secure Enclave Processor](https://www.blackhat.com/docs/us-16/materials/us-16-Mandt-Demystifying-The-Secure-Enclave-Processor.pdf)

#### OWASP Mobile Top 10 2016

- M1 - Improper Platform Usage
- M2 - Insecure Data Storage

#### OWASP MASVS

- V2.1: "System credential storage facilities are used appropriately to store sensitive data, such as user credentials or cryptographic keys."
- V2.2: "No sensitive data should be stored outside of the app container or system credential storage facilities."
- V2.3: "No sensitive data is written to application logs."
- V2.4: "No sensitive data is shared with third parties unless it is a necessary part of the architecture."
- V2.5: "The keyboard cache is disabled on text inputs that process sensitive data."
- V2.6:	"The clipboard is deactivated on text fields that may contain sensitive data."
- V2.7: "No sensitive data is exposed via IPC mechanisms."
- V2.8:	"No sensitive data, such as passwords or pins, is exposed through the user interface."
- V2.9: "No sensitive data is included in backups generated by the mobile operating system."
- V2.10: "The app removes sensitive data from views when backgrounded."
- V2.11:	"The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use."

#### CWE

- CWE-117 - Improper Output Neutralization for Logs
- CWE-200 - Information Exposure
- CWE-311 - Missing Encryption of Sensitive Data
- CWE-312 - Cleartext Storage of Sensitive Information
- CWE-359 - "Exposure of Private Information ('Privacy Violation')"
- CWE-522 - Insufficiently Protected Credentials
- CWE-524 - Information Exposure Through Caching
- CWE-532 - Information Exposure Through Log Files
- CWE-534 - Information Exposure Through Debug Log Files
- CWE-538 - File and Directory Information Exposure
- CWE-634 - Weaknesses that Affect System Processes
- CWE-922 - Insecure Storage of Sensitive Information

#### Tools

- [Fridump](https://github.com/Nightbringer21/fridump "Fridump")
- [objection](https://github.com/sensepost/objection "objection")
- [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
- [Burp Suite Professional](https://portswigger.net/burp)
