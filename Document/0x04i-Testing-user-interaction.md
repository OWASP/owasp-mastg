## Testing User Education
A lot has happened lately in terms of responsibilities that developers have to educate users on what they need to know.
This has shifted especially with the introduction of the [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/ "GDPR") in Europe. Ever since then, it is best to educate users on what is happening with their private data and why.
Next, it is a good practice to inform the user about how he can best use the application to ensure a secure processing of his information.
Both items will be dealt with here. Please not that this is the MSTG project and not a legal handbook. Therefore, we will not cover the GDPR and other possibly relevant laws here.


### Informing users on their private information
TODO: ADD CONTENT HERE!


### Informing the user on the best security practices
Here is a list of best practices where a user could be informed about:
- Fingerprint usage: when an app uses a fingerprint for authentication and it provides access to high risk transactions/information, then it might be a good idea to inform the user about the issues there can be when having mulitple fingerprints of other people registered to the device as well.
- Rooting/Jailbraking: when an app detected a root-level access or a jailbreak, it can be a good idea to inform the user of the fact that certain high-risk actions will carry additional risk due to the jailbroken/rooted status of the device.
- Specific credentials: when a user gets a recovery code, a password or a pin from the application (or sets one), it might be a good idea to instruct the user to never share this with anyone else and that only the app can request it.

### Other information you have to share (OSS information)
Given copyright laws, there is one more thing where the app-developer should inform the user about. It is about the fact that the app contains third party libraries. For each third party library, a developer should check whether the license of that third party library is adhered to correctly. This means in case of many open-source licenses, that a certain copyright statement needs to be presented somewhere in the source code of the application and sometimes in the application or in a website related to the application. For this, it is best to consult a legal specialists advice. An example can be found at [This blog](https://www.bignerdranch.com/blog/open-source-licenses-and-android/ "Example on license overview").

### References

#### OWASP MASVS

- V2.12: "The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app."

#### Example for open source license mentioning

- https://www.bignerdranch.com/blog/open-source-licenses-and-android/
