### <a name="OMTG-ENV-001"></a>OMTG-ENV-001: Test of App permissions

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

##### OWASP MASVS

- V6.1: "The app only requires the minimum set of permissions necessary."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### <a name="OMTG-ENV-002"></a>OMTG-ENV-002: Test validation of external input

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

##### OWASP MASVS

- V6.2: "All inputs from external sources are validated. This includes data received via the GUI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### <a name="OMTG-ENV-003"></a>OMTG-ENV-003: Test input sanitization

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

##### OWASP MASVS

- V6.3: "All user input is sanitized, including input obtained via the UI, as well as input originating from QR codes, NFC data, and other sources."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link



### <a name="OMTG-ENV-004"></a>OMTG-ENV-004: Test usage of custom URL schemes

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

##### OWASP MASVS

- V6.4: "The app does not export sensitive functionality via custom URL schemes."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link



### <a name="OMTG-ENV-005"></a>OMTG-ENV-005: Test for export of sensitive functionality

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

##### OWASP MASVS

- V6.5: "The app does not export sensitive functionality through IPC facilities."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link



### <a name="OMTG-ENV-006"></a>OMTG-ENV-006: Test for usage of JavaScript in WebViews

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

##### OWASP MASVS

- V6.6: "JavaScript is disabled in WebViews unless explicitly required."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### <a name="OMTG-ENV-007"></a>OMTG-ENV-007: Test for usage of file access in WebViews

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

##### OWASP MASVS

- V6.7: "File access is disabled in WebViews unless explicitly required."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### <a name="OMTG-ENV-008"></a>OMTG-ENV-008: Test for user supplied resources in WebViews

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

##### OWASP MASVS

- V6.9: "The app does not load user-supplied local resources into WebViews."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link


### <a name="OMTG-ENV-009"></a>OMTG-ENV-009: Test for exposed Java Objects in WebViews

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

##### OWASP MASVS

- V6.10: "If Java objects are exposed in a WebView, verify that the WebView only renders JavaScript contained within the app package."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link




### <a name="OMTG-ENV-010"></a>OMTG-ENV-010: Test for updating of Security Provider

#### Overview

Check <sup>[1]</sup>


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

##### OWASP MASVS

- V6.11: "The app leverages operating system features that allow updating of outdated system components."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Update Security Provider - https://developer.android.com/training/articles/security-gms-provider.html


##### Tools

* Tool - Link


## <a name="OMTG-ENV-011"></a>OMTG-ENV-011: Test for installation source

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

##### OWASP MASVS

- V6.12: "The app checks its installation source, and only runs if installed from a trusted source (e.g. Google Play Store / Apple App Store)."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link



## <a name="OMTG-ENV-012"></a>OMTG-ENV-012: Test for Root detection

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

##### OWASP MASVS

- V6.13: "The app detects whether it is being executed on a rooted or jailbroken device. Depending on the business requirement, users are warned, or the app is terminated if the device is rooted or jailbroken."

##### CWE

- CWE-XXX - Title

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx


##### Tools

* Tool - Link
