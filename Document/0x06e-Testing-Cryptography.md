## Testing Cryptography

### Verifying Cryptographic Key Management

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify


### Testing for Custom Implementations of Cryptography

#### Overview

The use of a non-standard algorithm is dangerous because a determined attacker may be able to break the algorithm and compromise whatever data has been protected. Well-known techniques may exist to break the algorithm.

#### White-box Testing

Carefully inspect all the crypto methods, especially those which are directly applied to the sensitive data. Pay close attention to seemingly standard but modified algorithms. Remember that encoding is not encryption! Any appearance of direct XORing might be a good sign to start digging deeper.

#### Black-box Testing

Although fuzzing of the custom algorithm might work in case of very weak crypto, the recommended approach would be to decompile the app and inspect the algorithm to see if custom encryption schemes is really the case (see "White-box Testing")

#### Remediation

When there is a need to store or transmit sensitive data, use strong, up-to-date cryptographic algorithms to encrypt that data. Select a well-vetted algorithm that is currently considered to be strong by experts in the field, and use well-tested implementations. As with all cryptographic mechanisms, the source code should be available for analysis.
Do not develop custom or private cryptographic algorithms. They will likely be exposed to attacks that are well-understood by cryptographers. Reverse engineering techniques are mature. If the algorithm can be compromised if attackers find out how it works, then it is especially weak.

##### OWASP MASVS
- V3.2: "The app uses proven implementations of cryptographic primitives"

##### OWASP Mobile Top 10
* M6 - Broken Cryptography

##### CWE
* CWE-327: Use of a Broken or Risky Cryptographic Algorithm

### Verifying the Configuration of Cryptographic Standard Algorithms

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing for Insecure and/or Deprecated Cryptographic Primitives

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify

### Testing Random Number Generation

#### Overview

[Provide a general description of the issue.]

#### Static Analysis

[Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.]

[Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>.]

##### With Source Code

##### Without Source Code

#### Dynamic Analysis

[Describe how to test for this issue by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.]

#### Remediation

[Describe the best practices that developers should follow to prevent this issue.]

#### References

##### OWASP Mobile Top 10 2014

* MX - Title - Link
* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

- CWE-XXX - Title
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

* Tool - Link
* Enjarify - https://github.com/google/enjarify
