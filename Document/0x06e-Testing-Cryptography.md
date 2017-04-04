## Testing Cryptography

### Verifying Cryptographic Key Management

#### Overview

-- TODO [Provide a general description of the issue "Verifying Cryptographic Key Management"] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- TODO [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Create content of ""Verifying Cryptographic Key Management" with source code] --

##### Without Source Code

-- TODO [Create content of "Verifying Cryptographic Key Management" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Verifying Cryptographic Key Management" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying Cryptographic Key Management".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update below reference "VX.Y" for "Verifying Cryptographic Key Management"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying Cryptographic Key Management"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add link to relevant tools for "Verifying Cryptographic Key Management"] --
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

-- TODO [Provide a general description of the issue "Verifying the Configuration of Cryptographic Standard Algorithms"] --

#### Static Analysis

Apple provides libraries with implementations of most commonly used cryptographic algorithms. A good point of reference is [Cryptographic Services Guide](https://developer.apple.com/library/content/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html). It contains broad documentation on how to use standard libraries to initialize and use cryptographic primitives, which is also useful when performing source code analysis. 
For black-box testing, more useful is native C API, for instance CommonCryptor, that is most frequently used when performing cryptographic operations. Source code is partially available at [opensource.apple.com](https://opensource.apple.com).

##### With Source Code

-- TODO [Create content for "Verifying the Configuration of Cryptographic Standard Algorithms" with source code] --

##### Without Source Code

If the app is using standard cryptographic implementations provided by Apple, the easiest way is to decompile the application and check for calls to functions from `CommonCryptor`, such as `CCCrypt`, `CCCryptorCreate`, etc. The [source code](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h) contains signatures of all functions. 
For instance, `CCCryptorCreate` has following signature:
```
CCCryptorStatus CCCryptorCreate(
	CCOperation op,             /* kCCEncrypt, etc. */
	CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
	CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
	const void *key,            /* raw key material */
	size_t keyLength,	
	const void *iv,             /* optional initialization vector */
	CCCryptorRef *cryptorRef);  /* RETURNED */
```

You can then compare all the `enum` types to understand which algorithm, padding and key material is being used. Pay attention to the keying material, if it's coming directly from a password (which is bad), or if it's comming from Key Generation Function (e.g. PBKDF2). 
Obviously, there are other non-standard libraries that your application might be using (for instance `openssl`), so you should check for these too. 

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Verifying the Configuration of Cryptographic Standard Algorithms" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Verifying the Configuration of Cryptographic Standard Algorithms".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add links to relevant tools for "Verifying the Configuration of Cryptographic Standard Algorithms"] --
* Enjarify - https://github.com/google/enjarify

### Testing for Insecure and/or Deprecated Cryptographic Primitives

#### Overview

-- TODO [Provide a general description of the issue "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>." ] --

##### With Source Code

-- TODO [Add content on "Testing for Insecure and/or Deprecated Cryptographic Primitives"  with source code] --

##### Without Source Code

-- TODO [Add content on "Testing for Insecure and/or Deprecated Cryptographic Primitives"  without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing for Insecure and/or Deprecated Cryptographic Primitives" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing for Insecure and/or Deprecated Cryptographic Primitives".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update below reference "VX.Y" for "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add links to relevant tools for "Testing for Insecure and/or Deprecated Cryptographic Primitives"] --
* Enjarify - https://github.com/google/enjarify

### Testing Random Number Generation

#### Overview

-- TODO [Provide a general description of the issue "Testing Random Number Generation".] --

#### Static Analysis

-- TODO [Describe how to assess this given either the source code or installer package (APK/IPA/etc.), but without running the app. Tailor this to the general situation (e.g., in some situations, having the decompiled classes is just as good as having the original source, in others it might make a bigger difference). If required, include a subsection about how to test with or without the original sources.] --

-- [Confirm purpose of remark "Use the &lt;sup&gt; tag to reference external sources, e.g. Meyer's recipe for tomato soup<sup>[1]</sup>."] --

##### With Source Code

-- TODO [Add content for "Testing Random Number Generation" with source code] --

##### Without Source Code

-- TODO [Add content for "Testing Random Number Generation" without source code] --

#### Dynamic Analysis

-- TODO [Describe how to test for this issue "Testing Random Number Generation" by running and interacting with the app. This can include everything from simply monitoring network traffic or aspects of the app’s behavior to code injection, debugging, instrumentation, etc.] --

#### Remediation

-- TODO [Describe the best practices that developers should follow to prevent this issue "Testing Random Number Generation".] --

#### References

##### OWASP Mobile Top 10 2014

* M3 - Insufficient Transport Layer Protection - https://www.owasp.org/index.php/Mobile_Top_10_2014-M3

##### OWASP MASVS

-- TODO [Update reference below "VX.Y" for "Testing Random Number Generation"] --
- VX.Y: "Requirement text, e.g. 'the keyboard cache is disabled on text inputs that process sensitive data'."

##### CWE

-- TODO [Add relevant CWE for "Testing Random Number Generation"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add links to relavant tools for "Testing Random Number Generation"] --
* Enjarify - https://github.com/google/enjarify
