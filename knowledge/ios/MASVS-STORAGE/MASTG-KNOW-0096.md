---
masvs_category: MASVS-STORAGE
platform: ios
title: Realm Databases
---

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

Access to the data depends on the encryption: unencrypted databases are easily accessible, while encrypted ones require investigation into how the key is managed - whether it's hardcoded or stored unencrypted in an insecure location such as shared preferences, or securely in the platform's KeyStore (which is best practice).
However, if an attacker has sufficient access to the device (e.g. jailbroken access) or can repackage the app, they can still retrieve encryption keys at runtime using tools like Frida. The following Frida script demonstrates how to intercept the Realm encryption key and access the contents of the encrypted database.

```javascript
function nsdataToHex(data) {
    var hexStr = '';
    for (var i = 0; i < data.length(); i++) {
        var byte = Memory.readU8(data.bytes().add(i));
        hexStr += ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }
    return hexStr;
}

function HookRealm() {
    if (ObjC.available) {
        console.log("ObjC is available. Attempting to intercept Realm classes...");
        const RLMRealmConfiguration = ObjC.classes.RLMRealmConfiguration;
        Interceptor.attach(ObjC.classes.RLMRealmConfiguration['- setEncryptionKey:'].implementation, {
            onEnter: function(args) {
                var encryptionKeyData = new ObjC.Object(args[2]);
                console.log(`Encryption Key Length: ${encryptionKeyData.length()}`);
                // Hexdump the encryption key
                var encryptionKeyBytes = encryptionKeyData.bytes();
                console.log(hexdump(encryptionKeyBytes, {
                    offset: 0,
                    length: encryptionKeyData.length(),
                    header: true,
                    ansi: true
                }));

                // Convert the encryption key bytes to a hex string
                var encryptionKeyHex = nsdataToHex(encryptionKeyData);
                console.log(`Encryption Key Hex: ${encryptionKeyHex}`);
            },
            onLeave: function(retval) {
                console.log('Leaving RLMRealmConfiguration.- setEncryptionKey:');
            }
        });

    }

}
```
