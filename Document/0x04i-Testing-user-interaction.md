# Mobile App User Interaction

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

Most of this is traditionally being covered in a privacy policy. However, this approach is not always optimal for users who would be require to read usually long and wordly policies. In order to address this and help users easily understand how their data is being collected, handled and shared, Google and Apple introduced new privacy labeling systems (very much along the lines of NIST's proposal for [Consumer Software Cybersecurity Labeling](https://www.nist.gov/system/files/documents/2021/11/01/Draft%20Consumer%20Software%20Labeling.pdf)):
- the App Store [Nutrition Labels](https://www.apple.com/privacy/labels/) (since 2020).
- the Google Play [Data Safety Labels](https://android-developers.googleblog.com/2021/05/new-safety-section-in-google-play-will.html) (since 2021).

As a new requirement on both platforms, it's vital that these labels are accurate in order to provide user assurance and mitigate developer abuse.


When additional data needs to be processed, you should ask the user for consent again. During that consent request it needs to be made clear how the user can revert from sharing the additional data. Similarly, when existing datasets of a user need to be linked, you should ask the user's consent about it.

You can learn more about this and other privacy related topics here:

- [iOS App Privacy Policy](https://developer.apple.com/documentation/healthkit/protecting_user_privacy#3705073)
- [iOS Privacy Details Section on the App Store](https://developer.apple.com/app-store/app-privacy-details/)
- [iOS Privacy Best Practices](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy)
- [Android App Privacy Policy](https://support.google.com/googleplay/android-developer/answer/9859455#privacy_policy)
- [Android Data Safety Section on Google Play](https://support.google.com/googleplay/android-developer/answer/10787469)
- [Android Privacy Best Practices](https://developer.android.com/privacy/best-practices)

#### Testing Data Privacy

You can use the following resources as a starting point for your analysis.

**Android:**
- [Review how the app collects and shares user data](https://developer.android.com/guide/topics/data/collect-share).
- Verify if the app performs [Data Access Auditing](https://developer.android.com/guide/topics/data/audit-access) (available for Android 11 (API level 30) and higher) and list all the used attribution tags. You can use the [DataAccessAuditingKotlin sample app](https://github.com/android/permissions-samples/tree/master/DataAccessAuditingKotlin) as a reference.
- Use the [Privacy Dashboard](https://developer.android.com/training/permissions/explaining-access#privacy-dashboard) from the Android settings (Android 12 (API level 31) and higher) to monitor app access to sensitive information.

**iOS:**

- Verify which [iOS Privacy Details](https://developer.apple.com/app-store/app-privacy-details/) does the app include on the App Store.
- Verify if and how the app is using the [App Tracking Transparency Framework](https://developer.apple.com/documentation/apptrackingtransparency).
- [Enable the App Privacy Report](https://developer.apple.com/documentation/network/privacy_management/inspecting_app_activity_data) from the iOS settings (iOS 15.2 and higher) to monitor app activity data. After using the app extensively, you can save the report as JSON file containing a collection of dictionaries of different types. Parse for the `type: "access"` to inspect all data access by category (camera, contacts, etc.) and the `type: "networkActivity"` to examine all network accesses.


These are some examples of common violations that you should report:
- An app collects device location but does not have a prominent disclosure explaining which feature uses this data and/or indicates the app's usage in the background.
- An app has a runtime permission requesting access to data before the prominent disclosure which specifies what the data is used for.
- An app that accesses a user's phone or contact book data and doesn't treat this data as personal or sensitive data subject to the above Privacy Policy, data handling, and Prominent Disclosure and Consent requirements.
- An app that records a user’s screen and doesn't treat this data as personal or sensitive data subject to this policy.

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
