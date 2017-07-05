## Testing Code Quality

### Testing for Injection Flaws

#### Overview

Injection flaws are a class of security vulnerability that occurs when user input is concatenated into backend queries or commands. By injecting meta characters, an attacker can inject malicious code which is then inadvertently interpreted as part of the command or query. For example, by manipulating a SQL query, an attacker could be able to retrieve arbitrary database records or manipulate the content of the database.

This vulnerability class is very prevalent in web services (including the endpoints connected to by mobile apps). They may also occur in the mobile app itself, but exploitable instances are much less common, as mobile apps usually act as clients and simply don't offer the attack surface necessary for viable attacks. For example, while a mobile app might query a local database, such mobile databases hardly store data that could usefully be extracted through SQL injection.

Nevertheless, viable attack scenarios are at least conceivable, and proper input validation should generally performed as practice.

##### Entry Points

Input from any untrusted source should be validated. Possible input vectors include the following:

- User interface
- URL schemes
- Input files received via Bluetooth, AirDrop or other means
- Pasteboards
- Application extensions

##### Common Injection Types

###### SQL Injection

SQL injection involves "injecting" SQL command characters into the input data, affecting the execution of the predefined SQL command. A successful SQL injection exploit can read and modify database data or (depending on the database server used) execute administrative commands.

Mobile apps on Android and iOS both use SQLite databases as a means of local data storage. SQL injection vulnerabilities occur when user input is concatenated into dynamic SQL statements without prior sanitization.

###### XML Injection

In an [XML injection attack](https://www.owasp.org/index.php/Testing_for_XML_Injection_%28OTG-INPVAL-008%29 "XML Injection in the OWASP Testing Guide"), the attacker injects XML meta characters to structurally alter XML content. This can be used to either compromise the logic of an XML-based application or service, or to exploit features of the XML parser processing the content.

In mobile apps, the trend goes towards REST/JSON-based services, so you won't see XML used that often. However, in the rare cases where user-supplied or otherwise untrusted content is used to construct XML queries and passed to local XML parsers, such as NSXMLParser on iOS and on Android, the input should be validated and escaped.

###### Local File Inclusion

#### Static Analysis

#### Dynamic Analysis

#### Remediation

- Verify that File System Access is disabled for any WebViews.

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation

### Testing for Memory Corruption Bugs in Native Code

#### Overview

Android apps are for the most part implemented in Java, which is inherently safe from all kinds of memory corruption issues. However, apps that come with native JNI libraries are susceptible to this kind of bug.

###### Buffer Overflows

###### Format String Vulnerabilities

#### Static Analysis

#### Dynamic Analysis

##### Input Fuzzing

The process of fuzzing is to repeatedly feeding an application with various combinations of input value, with the goal of finding security vulnerabilities in the input-parsing code. There were instances when the application simply crashes, but also were also occasions when it did not crash but behave in a manner which the developers did not expect them to be, which may potentially lead to exploitation by attackers.  

Fuzzing, is a method for testing software input validation by feeding it intentionally malformed input. Below are the steps in performing the fuzzing:

- Identifying a target
- Generating malicious inputs
- Test case delivery
- Crash monitoring

Input fuzzing will not be discussed in great detail in this guide. Refer to the [OWASP Fuzzing Guide](https://www.owasp.org/index.php/Fuzzing) for more information.

Note: Fuzzing only detects software bugs. Classifying this issue as a security flaw requires further analysis by the researcher.

- **Protocol adherence** - for data to be handled at all by an application, it may need to adhere relatively closely to a given protocol (e.g. HTTP) or format (e.g. file headers). The greater the adherence to the structure of a given protocol or format, the more likely it is that meaningful errors will be detected in a short time frame. However, it comes at the cost of decreasing the test surface, potentially missing low level bugs in the protocol or format.

- [**Fuzz Vectors**](https://www.owasp.org/index.php/OWASP_Testing_Guide_Appendix_C:_Fuzz_Vectors "OWASP Testing Guide: Fuzzing") - fuzz vectors may be used to provide a list of known risky values likely to cause undefined or dangerous behavior in an app. Using such a list focuses tests more closely on likely problems, reducing the number of false positives and decreasing the test execution time.

#### Remediation

- Avoid using unsafe string functions such as strcpy, strcat, strncat, strncpy, sprint, vsprintf, gets, and so on.
- User input or other untrusted data should never be used as part of format strings.

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation

### Testing for Cross-Site Scripting Flaws

#### Overview

Cross-site scripting (XSS) flaws enable attackers to inject client-side scripts into web pages viewed by users. This type of flaw is very common in the web applications. If the user views the injected script in their browser, the attacker can bypass the same origin policy and do pretty much everything in the context of vulnerable website (e.g. stealing session cookies, logging key presses, or performing arbitrary actions).

In the context of mobile apps, XSS risks are far less prevalent for the simple reason that mobile apps aren't web browsers. However, apps that use WebView components such as <code>UIWebView</code>on iOS and <code>WebView</code> on Android are potentially vulnerable to attacks. An older, but well-known example is the [local XSS issue in the Skype app for iOS identified by Phil Purviance](https://superevr.com/blog/2011/xss-in-skype-for-ios "Superevr.com - XSS in Skype for iOS").

#### Static Analysis

#### Dynamic Analysis

#### Remediation

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation
