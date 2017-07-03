## Testing Code Quality

### Testing for Injection Flaws

#### Overview

Injection flaws are a class of security vulnerability that occurs when user input is concatenated into backend queries or commands. By injecting meta characters, an attacker can inject malicious code which is then inadvertently interpreted as part of the command or query. For example, by manipulating a SQL query, an attacker could be able to retrieve arbitrary database records or manipulate the contents of the database. 

This vulnerability class is very prevalent in web services (including the endpoints connected to by mobile apps). They may also occur in the mobile app itself, but exploitable instances are much less common, as mobile apps usually act as clients and simply don't offer the attack surface necessary for viable attacks. For example, while a mobile app might query a local database, such mobile databases hardly store data that could usefully be extracted through SQL injection.

#### Static Analysis

#### Dynamic Analysis

#### Remediation

#### References

##### OWASP Mobile Top 10 2016

* M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

* V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

* CWE-20 - Improper Input Validation

### Testing for Memory Corruption Bugs in Native Code

#### Overview

#### Static Analysis

#### Dynamic Analysis

#### Remediation

#### References

##### OWASP Mobile Top 10 2016

* M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

* V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

* CWE-20 - Improper Input Validation


### Testing for Cross-Site Scripting Flaws

#### Overview

#### Static Analysis

#### Dynamic Analysis

#### Remediation

#### References

##### OWASP Mobile Top 10 2016

* M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

* V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

* CWE-20 - Improper Input Validation

