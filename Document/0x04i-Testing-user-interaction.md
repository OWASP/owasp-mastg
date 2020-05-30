# Testing User Interaction

## Testing User Education (MSTG-STORAGE-12)

A lot has happened lately in terms of responsibilities that developers have to educate users on what they need to know.
This has shifted especially with the introduction of the [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/ "GDPR") in Europe. Ever since then, it is best to educate users on what is happening with their private data and why.
Additionally, it is a good practice to inform the user about how to use the application properly. This should ensure a secure handling and processing of the user's information.
Next, a user should be informed on what type of device data the app will access, whether that is PII or not.
Last, you need to share OSS related information with the user.
All four items will be covered here.

> Please note that this is the MSTG project and not a legal handbook. Therefore, we will not cover the GDPR and other possibly relevant laws here.

### Informing users on their private information

When you need personal information from a user for your business process, the user needs to be informed on what you do with the data and why you need it. If there is a third party doing the actual processing of the data, you should inform the user about that too. Lastly, there are three processes you need to support:

- **The right to be forgotten**: Users need to be able to request the deletion of their data, and be explained how to do so.
- **The right to correct data**: Users should be able to correct their personal information at any time, and be explained how to do so.
- **The right to access user data**: Users should be able to request all information that the application has on them, and be explained how to request this information.

Most of this can be covered in a privacy policy, but make sure that it is understandable by the user.

When additional data needs to be processed, you should ask the user for consent again. During that consent request it needs to be made clear how the user can revert from sharing the additional data. Similarly, when existing datasets of a user need to be linked, you should ask the user's consent about it.

### Informing the user on the best security practices

Here is a list of best practices where a user could be informed of:

- **Fingerprint usage**: When an app uses a fingerprint for authentication and it provides access to high risk transactions/information, inform the user about the issues there can be when having multiple fingerprints of other people registered to the device as well.
- **Rooting/Jailbreaking**: When an app detects a rooted or jailbroken device, inform the user of the fact that certain high-risk actions will carry additional risk due to the jailbroken/rooted status of the device.
- **Specific credentials**: When a user gets a recovery code, a password or a pin from the application (or sets one), instruct the user to never share this with anyone else and that only the app will request it.
- **Application distribution**: In case of a high-risk application it is recommended to communicate what the official way of distributing the app is. Otherwise, users might use other channels in which they download a compromised version of the application.

### Access to Device Data

Although partially covered by the Google Play Store and the Apple App Store, you still need to explain to the user which services your app consumes and why. For instance:

- Does your app require access to the contact list?
- Does your app need access to location services of the device?
- Does your app use device identifiers to identify the device?

Explain the user why your app needs to do this kind of things. More information on this subject can be found at the [Apple Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/ "Apple Human Interface Guidelines") and the [Android App permissions best practices](https://developer.android.com/training/permissions/requesting.html#explain "Android App permissions best practices").

### Other Information You Have to Share (OSS Information)

Given copyright laws, you must make sure you inform the user on any third party libraries that are used in the app. For each third party library you should consult the license to see if certain information (such as copyright, modifications, original author, ...) should be presented to the user. For this, it is best to request legal advice from a specialist. An example can be found at [a blog post from Big Nerd Ranch](https://www.bignerdranch.com/blog/open-source-licenses-and-android/ "Example on license overview"). Additionally, the website [TL;DR - Legal](https://tldrlegal.com/ "TL;DR - Legal") can help you in figuring out what is necessary for each license.

## References

### OWASP MASVS

- MSTG-STORAGE-12: "The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app."

### Example for open source license mentioning

- <https://www.bignerdranch.com/blog/open-source-licenses-and-android/>

### Website to Help with Understanding Licenses

- <https://tldrlegal.com/>

### Guidance on Permission Requesting

- Apple Human Interface Guidelines - <https://developer.apple.com/design/human-interface-guidelines/ios/app-architecture/requesting-permission/>
- Android App permissions best practices - <https://developer.android.com/training/permissions/requesting.html#explain>
