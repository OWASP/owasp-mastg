## Testing User Education
A lot has happened lately in terms of responsibilities that developers have to educate users on what they need to know.
This has shifted especially with the introduction of the [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/ "GDPR") in Europe. Ever since then, it is best to educate users on what is happening with their private data and why.
Next, it is a good practice to inform the user about how he can best use the application to ensure a secure processing of his information.
Both items will be dealt with here. Please not that this is the MSTG project and not a legal handbook. Therefore, we will not cover the GDPR and other possibly relevant laws here.


### Informing users on their private information
When you need personal information from a user for your business process, then the user needs to be informed what you do with the data and why you need it. If there is a third party doing the actual processing of the data, then the user should be informed about that. Lastly, there are three processes you need to support:
- The right to be forgotten: A user needs to know how - and be be able to request the deletion of his data.
- The right to correct the data: the user should know - and should be able to correct his personal information at any time.
- The right to access by the data subject: the user always has the right to request all the data that you have on him/her.
Most of this can be covered in a privacy policy, however: make sure that it is readable by a customer.

When additional data needs to be processed, then the user should be asked for consent again. During that consent it needs to be clear how the user can revert from sharing the additional data. Similarly, when existing datasets of a user need to be linked, the user should be asked for consent about it.


### Informing the user on the best security practices
Here is a list of best practices where a user could be informed about:
- Fingerprint usage: when an app uses a fingerprint for authentication and it provides access to high risk transactions/information, then it might be a good idea to inform the user about the issues there can be when having mulitple fingerprints of other people registered to the device as well.
- Rooting/Jailbraking: when an app detected a root-level access or a jailbreak, it can be a good idea to inform the user of the fact that certain high-risk actions will carry additional risk due to the jailbroken/rooted status of the device.
- Specific credentials: when a user gets a recovery code, a password or a pin from the application (or sets one), it might be a good idea to instruct the user to never share this with anyone else and that only the app can request it.
- Insecure store usage: in case of a high-risk applicaton it is recommended to communicate what the official way of distributing the app is. Otherwise, users might use other channels in which they download a compromised version of the application.

### Other information you have to share (OSS information)
Given copyright laws, there is one more thing where the app-developer should inform the user about. It is about the fact that the app contains third party libraries. For each third party library, a developer should check whether the license of that third party library is adhered to correctly. This means in case of many open-source licenses, that a certain copyright statement needs to be presented somewhere in the source code of the application and sometimes in the application or in a website related to the application. For this, it is best to consult a legal specialists advice. An example can be found at [This blog](https://www.bignerdranch.com/blog/open-source-licenses-and-android/ "Example on license overview").

### References

#### OWASP MASVS

- V2.12: "The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app."

#### Example for open source license mentioning

- https://www.bignerdranch.com/blog/open-source-licenses-and-android/
