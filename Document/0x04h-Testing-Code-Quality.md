## Testing Code Quality

Mobile app developers use a wide variety of programming languages and frameworks. As such, common vulnerabilities such as SQL injection, buffer overflows, and cross-site scripting (XSS), may manifest in apps when neglecting secure programming practices.
 
In the following chapter, we'll provide an overview of the most common vulnerability classes frequently surfacing in mobile apps. In later sections, we will cover OS-specific instances and exploit mitigation features.

### Testing for Injection Flaws

#### Overview

An *injection flaw* describes a class of security vulnerability occurring when user input is inserted into backend queries or commands. By injecting meta characters, an attacker can execute malicious code as is is inadvertently interpreted as part of the command or query. For example, by manipulating a SQL query, an attacker could retrieve arbitrary database records or manipulate the content of the backend database.

Vulnerabilities of this class are most prevalent in server-side web services. Exploitable instances also exist within mobile apps, but occurrences are less common, plus the attack surface is smaller.
 
For example, while an app might query a local SQLite database, such databases usually do not store sensitive data (assuming the developer followed basic security practices). This makes SQL injection an non-viable attack vector. Nevertheless, exploitable injection vulnerabilities sometimes occur, meaning proper input validation is a necessary best practice for programmers.

##### Common Injection Types

###### SQL Injection

A *SQL injection* attack involves integrating SQL commands into input data, mimicking the syntax of a predefined SQL command. A successful SQL injection attack allows the attacker to read or write to the database and possibly execute administrative commands, depending on the permissions granted by the server.

Apps on both Android and iOS use SQLite databases as a means to control and organize local data storage. Assume an Android app handles local user authentication by storing the user credentials in a local database (a poor programming practice we’ll overlook for the sake of this example). Upon login, the app queries the database to search for a record with the user name and password entered by the user:

```java=
SQLiteDatabase db;

String sql = "SELECT * FROM users WHERE username = '" +  username + "' AND password = '" + password +"'";

Cursor c = db.rawQuery( sql, null );

return c.getCount() != 0;
```

Let's further assume an attacker enters the following values into the "username" and "password" fields:


```
username = 1' or '1' = '1
password = 1' or '1' = '1
```

This results in the following query:

```
SELECT * FROM users WHERE username='1' OR '1' = '1' AND Password='1' OR '1' = '1' 
```

Because the condition <code>'1' = '1'</code> always evaluates as true, this query return all records in the database, causing the login function to return "true" even though no valid user account was entered.

One real-world instance of client-side SQL injection was discovered by Mark Woods within the "Qnotes" and "Qget" Android apps running on QNAP NAS storage appliances. These apps exported content providers vulnerable to SQL injection, allowing an attacker to retrieve the credentials for the NAS device. A detailed description of this issue can be found on the [Nettitude Blog] (http://blog.nettitude.com/uk/qnap-android-dont-provide "Nettitude Blog - "QNAP Android: Don't Over Provide").

###### XML Injection

In an *XML injection* attack, the attacker injects XML meta characters to structurally alter XML content. This can be used to either compromise the logic of an XML-based application or service, as well as possibly allow an attacker to exploit the operation of the XML parser processing the content.

A popular variant of this attack is [XML Entity Injection (XXE)](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing). Here, an attacker injects an external entity definition containing an URI into the input XML. During parsing, the XML parser expands the attacker-defined entity by accessing the resource specified by the URI. The integrity of the parsing application ultimately determines capabilities afforded to the attacker, where the malicious user could do any (or all) of the following: access local files, trigger HTTP requests to arbitrary hosts and ports, launch a [cross-site request forgery (CSFR)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) attack, and cause a denial-of-service condition. The OWASP web testing guide contains the [following example for XXE](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008)):

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
```

In this example, the local file `/dev/random` is opened where an endless stream of bytes is returned, potentially causing a denial-of-service.

The current trend in app development focuses mostly on REST/JSON-based services as XML is becoming less common. However, in the rare cases where user-supplied or otherwise untrusted content is used to construct XML queries, it could be interpreted by local XML parsers, such as NSXMLParser on iOS. As such, said input should always be validated and meta-characters should be escaped.

#### Finding Injection Flaws

Injection attacks against an app are most likely to occur through inter-process communication (IPC) interfaces, where a malicious app attacks another app running on the device. Attacks executed through the user interface or network services ar less common.

Locating a potential vulnerabilities begins by either:

- Identifying possible entry points for untrusted input then tracing from those locations to see if the destination contains potentially vulnerable functions.
- Identifying known, dangerous library / API calls (e.g. SQL queries) and then checking whether unchecked input successfully interfaces with respective queries.

During a manual security review, you should employ a combination of both techniques. In general, untrusted inputs enter mobile apps through the following channels:

- IPC calls
- Custom URL schemes
- QR codes
- Input files received via Bluetooth, NFC, or other means
- Pasteboards
- User interface

We will cover details related to input sources and potentially vulnerable APIs for each mobile OS in the OS-specific testing guides.

#### Remediation

In most other cases, vulnerabilities can be prevented by following programming best practices, such as:

- Always be type-check untrusted inputs and/or validate the inputs using a white-list of acceptable values. 
- Use prepared statements with variable binding (i.e. parameterized queries) when performing database queries. If prepared statements are defined, user-supplied data and SQL code are automatically separated.
- When parsing XML data, ensure the parser application is configured to reject resolution of external entities in order to prevent XXE attack.

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation

### Testing for Memory Corruption Bugs in Native Code

#### Overview

Memory corruption bugs are a popular mainstay with hackers. This class of bug results from a programming error that causes the program to access an unintended memory location. Under the right conditions, attackers can capitalize on this behavior to hijack the execution flow of the vulnerable program and execute arbitrary code. This kind of vulnerability occurs in a number of ways:

- Buffer overflows: This describes a programming error where an app writes beyond an allocated memory range for a particular operation. An attacker can use this flaw to overwrite important control data located in adjacent memory, such as function pointers. Buffer overflows were formerly the most common type of memory corruption flaw, but have become less prevalent over the years due to a number of factors. Notably, awareness among developers of the risks in using unsafe C library functions is now a common best practice plus, catching buffer overflow bugs is relatively simple. However, it is still worth testing for such defects.

- Out-of-bounds-access: Buggy pointer arithmetic may cause a pointer or index to reference a position beyond the bounds of the intended memory structure (e.g. buffer or list). When an app attempts to write to an out-of-bounds address, a crash or unintended behavior occurs. If the attacker can control the target offset and manipulate the content written to some extent, [code execution exploit is likely possible](http://www.zerodayinitiative.com/advisories/ZDI-17-110/).

- Dangling pointers: These occur when an object with an incoming reference to a memory location is deleted or deallocated, but the object pointer is not reset. If the program later uses the *dangling* pointer to call a virtual function of the already deallocated object, it is possible to hijack execution by overwriting the original vtable pointer. Alternatively, it is possible to read or write object variables or other memory structures referenced by a dangling pointer.

- Use-after-free: This refers to a special case of dangling pointers referencing released (deallocated) memory. After a memory address is cleared, all pointers referencing the location become invalid, causing the memory manager to return the address to a pool of available memory. When this memory location is eventually re-allocated, accessing the original pointer will read or write the data contained in the newly allocated memory. This usually leads to data corruption and undefined behavior, but crafty attackers can set up the appropriate memory locations to leverage control of the instruction pointer.

- Integer overflows: When the result of an arithmetic operation exceeds the maximum value for the integer type defined by the programmer, this results in the value "wrapping around" the maximum integer value, inevitably resulting in a small value being stored. Conversely, when the result of an arithmetic operation is smaller than the minimum value of the integer type, an *integer underflow* occurs where the result is larger than expected. Whether a particular integer overflow/underflow bug is exploitable depends on how the integer is used – for example, if the integer type were to represent the length of a buffer, this could create a buffer overflow vulnerability.

- Format string vulnerabilities: When unchecked user input is passed to the format string parameter of the <code>printf()</code> family of C functions, attackers may inject format tokens such as ‘%c’ and ‘%n’ to access memory. Format string bugs are convenient to exploit due to their flexibility. Should a program output the result of the string formatting operation, the attacker can read and write to memory arbitrarily, thus bypassing protection features such as ASLR.

The primary goal in exploiting memory corruption is usually to redirect program flow into a location where the attacker has placed assembled machine instructions referred to as *shellcode*. On iOS, the data execution prevention feature (as the name implies) prevents execution from memory defined as data segments. To bypass this protection, attackers leverage return-oriented programming (ROP). This process involves chaining together small, pre-existing code chunks ("gadgets") in the text segment where these gadgets may execute a function useful to the attacker or, call <code>mprotect</code> to change memory protection settings for the location where the attacker stored the *shellcode*.

Android apps are, for the most part, implemented in Java which is inherently safe from memory corruption issues by design. However, *native apps* utilizing JNI libraries are susceptible to this kind of bug.

#### Static Analysis

Static code analysis of low-level code is a complex topic that could easily fill its own book. Automated tools such as [RATS](https://code.google.com/archive/p/rough-auditing-tool-for-security/downloads "RATS - Rough auditing tool for security") combined with limited manual inspection efforts are usually sufficient to identify low-hanging fruits. However, memory corruption conditions often stem from complex causes. For example, a use-after-free bug may actually be the result of an intricate, counter-intuitive race condition not immediately apparent. Bugs manifesting from deep instances of overlooked code deficiencies are generally discovered through dynamic analysis or by testers who invest time to gain a deep understanding of the program.

##### Buffer and Integer Overflows

The following code snippet shows a simple example for a condition resulting in a buffer overflow vulnerability.

```c
 void copyData(char *userId) {  
    char  smallBuffer[10]; // size of 10  
    strcpy(smallBuffer, userId);
 }  
```

- To identify potential buffer overflows, look for uses of unsafe string functions (<code>strcpy</code>, <code>strcat</code>, other functions beginning with the “str” prefix, etc.) and potentially vulnerable programming constructs, such as copying user input into a limited-size buffer. The following should be considered red flags for unsafe string functions:

    - <code>strcat</code>
    - <code>strlcat</code>
    - <code>strcpy</code>
    - <code>strncat</code>
    - <code>strlcat</code>
    - <code>strncpy</code>
    - <code>strlcpy</code>
    - <code>sprintf</code>
    - <code>snprintf</code>
    - <code>gets</code>

- Look for instances of copy operations implemented as “for” or “while” loops and verify length checks are performed correctly;

- When using integer variables for array indexing, buffer length calculations, or any other security-critical operation, verify that  unsigned integer types are used and perform precondition tests are performed to prevent the possibility of integer wrapping.

#### Dynamic Analysis

Memory corruption bugs are best discovered via input fuzzing: an automated black-box software testing technique in which malformed data is continually sent to an app to survey for potential vulnerability conditions. During this process, the application is monitored and for malfunctions and crashes. Should a crash occur, the hope (at least for security testers) is that the conditions creating the crash reveal an exploitable security flaw.

Fuzz testing techniques or scripts (often called “fuzzers”) will typically generate multiple instances of structured input in a semi-correct fashion. Essentially, the values or arguments generated are at least partially accepted by the target application, yet also contain invalid elements, potentially triggering input processing flaws and unexpected program behaviors. A good fuzzer exposes a substantial amount of possible program execution paths (i.e. high coverage output). Inputs are either generated from scratch ("generation-based") or derived from mutation known, valid input data ("mutation-based").

For more information on fuzzing, refer to the [OWASP Fuzzing Guide](https://www.owasp.org/index.php/Fuzzing).

#### Remediation

- Avoid using unsafe string functions such as <code>strcpy</code>, most other functions beginning with the “str” prefix, <code>sprint</code>, <code>vsprintf</code>, <code>gets</code>, and so on.
- If you are using C++, use the ANSI C++ string class.
- If you are writing code in Objective-C, use the NSString class. If you are writing code in C on iOS, you should use CFString, the Core Foundation representation of a string.
- Do not concatenate untrusted data into format strings.

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation

### Testing for Cross-Site Scripting Flaws

#### Overview

Cross-site scripting (XSS) flaws enable attackers to inject client-side scripts into web pages viewed by users. This type of vulnerability is prevalent in web applications. When a user views the injected script in a browser, the attacker gains the ability to bypass the same origin policy, enabling a wide variety of exploits (e.g. stealing session cookies, logging key presses, performing arbitrary actions, etc.).

In the context of *native apps*, XSS risks are far less prevalent for the simple reason these kinds of applications do not rely on a web browser. However, apps using WebView components, such as ‘UIWebView’ on iOS and ‘WebView’ on Android, are potentially vulnerable to such attacks.

An older but well-known example is the [local XSS issue in the Skype app for iOS, first identified by Phil Purviance]( https://superevr.com/blog/2011/xss-in-skype-for-ios). The Skype app failed to properly encode the name of the message sender, allowing an attacker to inject malicious JavaScript to be executed when a user views the message. In his proof-of-concept, Phil showed how to exploit the issue and steal a user's address book.

#### Static Analysis

Take a close look at any WebViews present and investigate for untrusted input rendered by the app.

XSS issues may exist if the URL opened by WebView can be exploited, where an attacker may gain full or partial control. The following example is from an XSS issue in the [Zoho Web Service, reported by Linus Särud]( https://labs.detectify.com/2015/02/20/finding-an-xss-in-an-html-based-android-application/).

```java
webView.loadUrl("javascript:initialize(" + myNumber + ");");
```

If WebView is used to display a remote website, the burden of escaping HTML shifts to the server side. If an XSS flaw exists on the webserver, this can be used to execute script in the context of the WebView. As such, it is important to perform static analysis of the web application source code.

#### Dynamic Analysis

The best method to test for XSS issues requires using a combination of manual and automatic input fuzzing – injecting HTML tags and special characters into all available input fields to verify the web application denies invalid inputs or escapes the HTML meta-characters in its output.

A [reflected XSS attack]( https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001)) refers to an exploit where malicious code is injected into a HTTP response. To test for these attacks, automated input fuzzing is considered to be the best method. For example, the [BURP Scanner](https://portswigger.net/burp/)is highly effective in identifying vulnerabilities for such exploits. As always with automated analysis, ensure all input vectors are covered with a manual review of testing parameters.

#### Remediation

Security testers commonly use the infamous JavaScript message box to demonstrate exploitation via XSS. Inadvertently, developers sometimes assume by blacklisting the <code>alert()</code> command, this serves as an acceptable solution but this is not the case. Instead, preventing XSS is best accomplished by following general programming best practices.

- Avoid placing untrusted data in an HTML document unless it is absolutely necessary. If you do, be aware of the context in which the data is rendered. Note: escaping rules become complicated when HTML is nested within other code, for example, rendering a URL located inside a JavaScript block.

- Utilize appropriate encoding for escape characters, such as HTML entity encoding. This will prevent switching into a context where execution becomes a possibility, such as for script, style, or event handlers.

Make to consider how data will be rendered in a response for escapes. For example, there are six HTML control characters that must be escaped to remove vulnerability situations:

| Character  | Escaped      |
| :-------------: |:-------------:|
| & | &amp;amp;| 
| < | &amp;lt; | 
| > | &amp;gt;| 
| " | &amp;quot;| 
| ' | &amp;#x27;| 
| / | &amp;#x2F;| 

For a comprehensive list of escaping rules and other prevention measures, refer to the [OWASP XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet "OWASP XSS Prevention Cheat Sheet").

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation
