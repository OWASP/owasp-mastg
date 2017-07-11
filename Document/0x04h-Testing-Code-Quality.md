## Testing Code Quality

Mobile app developers use a wide variety of programming languages and frameworks. Many classical vulnerabilities, such as SQL injection, buffer overflows and cross-site scripting, can occur in mobile apps if secure programming practices are followed. In the following chapter, we'll give an overview of some common vulnerability classes. OS-specific details and exploit mitigation features will be discussed in later sections.

### Testing for Injection Flaws

#### Overview

Injection flaws are a class of security vulnerability that occurs when user input is concatenated into backend queries or commands. By injecting meta characters, an attacker can inject malicious code which is then inadvertently interpreted as part of the command or query. For example, by manipulating a SQL query, an attacker could retrieve arbitrary database records or manipulate the content of the backend database.

Vulnerability of this class are prevalent in web services, including the endpoints connected to by mobile apps. They also exist in mobile apps, but exploitable instances are less common, and the attack surface is smaller. For example, while a mobile app might query a local SQLite database, such databases usually don't store sensitive data that would make SQL injection a viable attack vector (or at least they shouldn't - if they do, it's a sign of broken design). Nevertheless, exploitable injection vulnerabilities do sometimes occur, and proper input validation should generally performed as best practice.

##### Common Injection Types

###### SQL Injection

SQL injection involves "injecting" SQL command characters into input data, affecting the semantics of a predefined SQL command. A successful SQL injection exploit can read and modify database data or (depending on the database server used) execute administrative commands.

Mobile apps on Android and iOS both use SQLite databases as a means of local data storage. SQL injection vulnerabilities occur when user input is concatenated into dynamic SQL statements without prior sanitization.

Assume an Android app that implements local user authentication by storing the user credentials in a local database (this isn't a good idea anyway, but let's ignore that for the sake of this example). Upon login, the app queries the database to search for a record with the user name and password entered by the user:

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

One real-world instance of client-side SQL injection was found by Mark Woods in the "Qnotes" and "Qget" Android apps running on QNAP NAS storage appliances. These apps implemented content providers vulnerable to SQL injection, allowing an attacker to retrieve the credentials for the NAS device. A detailed description of this issue can be found on the [Nettitude Blog](http://blog.nettitude.com/uk/qnap-android-dont-provide "Nettitude Blog - "QNAP Android: Don't Over Provide").

###### XML Injection

In an [XML injection attack](https://www.owasp.org/index.php/Testing_for_XML_Injection_%28OTG-INPVAL-008%29 "XML Injection in the OWASP Testing Guide"), the attacker injects XML meta characters to structurally alter XML content. This can be used to either compromise the logic of an XML-based application or service, or to exploit features of the XML parser processing the content.

A popular variant of variant of this attack is XML Entity Injection (XXE). In this variant, the attacker injects an external entity definition containing an URI into the input XML. During parsing the input, the XML parser expands the attacker-defined entity by accessing the resource specified by the URI. The attacker can use this to gain access to local files, trigger http requests to arbitrary hosts and ports, and cause a denial-of-service condition. The OWASP web testing guide contains the [following example for XXE](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008)):

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
```

In this example, the local file `/dev/random` is opened. This file returns an endless stream of bytes, potentially causing a denial-of-service.

In mobile apps, the trend goes towards REST/JSON-based services, so you won't see XML used that often. However, in the rare cases where user-supplied or otherwise untrusted content is used to construct XML queries and passed to local XML parsers, such as NSXMLParser on iOS and on Android, the input should be validated and escaped.

#### Finding Injection Flaws

Injection attacks in mobile apps are more likely to occur through IPC interfaces (i.e. a malicious app targeting a vulnerable app) than being performed through the user interface or network services. The analysis starts either by:

- Identifying possible entry points for untrusted input, and then tracing those inputs to see whether potentially vulnerable functions are reached, or
- Identifying known dangerous library / API calls (e.g. SQL queries) and then checking whether unchecked input reaches the queries.

In a manual security review you'll normally use a combination of both techniques. In general, untrusted inputs enter mobile apps through the following channels:

- IPC calls
- Custom URL schemes
- QR codes
- Input files received via Bluetooth, NFC, or other means
- Pasteboards
- User interface

You'll find more details on input sources and potentially vulnerable APIs for each mobile OS in the OS-specific testing guides.

#### Remediation

Untrusted inputs should always be type-checked and/or validated using a white-list of acceptable values. Besides that, in many cases vulnerabilities can be prevented by following programming best practices, such as:

- Use prepared statements with variable binding (aka parameterized queries) when doing database queries. If prepared statements are used, user-supplied data and SQL code are automatically kept separate;
- When parsing XML, make sure that the parser is configured to disallow resolution of external entities.

#### References

##### OWASP Mobile Top 10 2016

- M7 - Poor Code Quality - https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality

##### OWASP MASVS

- V6.2: "All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources."

##### CWE

- CWE-20 - Improper Input Validation

### Testing for Memory Corruption Bugs in Native Code

#### Overview

Memory corruption bugs are a popular mainstay with hackers. In this class of bugs, some programming error leads to a condition where contents of a unintended memory location are modified. Under the right conditions, attackers can exploit this behavior to hijack the execution flow  of the vulnerable program and execute arbitrary code. This kind of vulnerability can occur in a number of ways.

- Buffer Overflows: The app writes beyond the memory allocated for a particular operation. This allows the attacker to overwrite important control data located in adjacent memory, such as function pointers. Buffer overflows used to be the most common type of memory corruption flaw, but have become less prevalent over the years due to a number of factors. Notably, most developers have become aware of the risks in using unsafe C library functions, and catching buffer overflow bugs is comparably easy. Nevertheless, they haven't completely vanished, and are still worth testing for.

- Out-of-bounds-access: Buggy pointer arithmetic causes a pointer or index to point to a position beyond the bounds of the intended memory structure (e.g. buffer or list). Attempts to write the out-of-bounds address will cause a crash or unintended behavior. If the attacker can control the target offset and content being written to some extent, [code execution exploit is likely possible](http://www.zerodayinitiative.com/advisories/ZDI-17-110/).

- Dangling pointers: These occur when an object that has an incoming reference is deleted or deallocated, but the the pointer still points to the memory location of the deallocated object. If the program later uses the pointer to call a virtual function, of the (already deallocated) object, it is possible to hijack execution by setting up memory such that the original vtable pointer is overwritten. Alternatively, it is possible to read or write object variables or other memory structures referenced by the dangling pointers.

- Use-after-free: A special case of dangling pointers that point to freed (deallocated) memory. When memory is freed, all pointers into it become invalid, and the memory manager returns it to the pool of available memory. When at some point the same memory is re-allocated, accessing the original pointer will read or write the data contained in the newly allocated memory. When this happens unintentionally, it usually leads to data corruption and undefined behavior, but crafty attackers can to set up memory in just the right ways leverage to gain control of the instruction pointer.

- Integer overflows: When the result of an arithmetic operation exceeds the maximum size of the integer type chosen by the programmer, the resulting value will "wrap around" the maximum value and end up being much smaller than expected. On the other end of the spectrum, when the result of an arithmetic operation is smaller than the minimum value of the integer type, an integer *underflow* occurs and the result is much larger than expected. Whether a particular integer overflow/underflow bug is exploitable depends on how the integer is used: For example, if the integer represents the length of buffer length being allocated, an overflow can result in a buffer that is too small to hold the data to be copied into it, causing buffer overflow vulnerability.

- Format string vulnerabilities: When unchecked user input is passed to the format string parameter of printf()-family C functions, attackers may inject format tokens such as %c and %n to access memory. Format string bugs are convenient to exploit due to their flexibility: If the program outputs the result of the string formatting operation, the attacker can read and write memory arbitrarily, thus bypassing protection features such as ASLR.

In most cases, the goal in exploiting memory corruption is modifying redirecting the program flow to a location where the attacker has placed assembled machine instructions referred to as shellcode. On iOS, the data execution prevention feature (as the name implies) prevents memory in data segments from being executed. To bypass this protection, attackers leverage return-oriented programming (ROP), which involves chaining together small, pre-existing code chunks ("gadgets") in the text segment. These gadgets may then execute functionality useful to the attacker, or call <code>mprotect</code> to change memory protection settings on the location of the shellcode.

Android apps are for the most part implemented in Java which is inherently safe from memory corruption issues. However, apps that come with native JNI libraries are susceptible to this kind of bug. 

#### Static Analysis

Static code analysis of low-level code is a complex topic that could easily fill its own book. Automated tools such as [RATS](https://code.google.com/archive/p/rough-auditing-tool-for-security/downloads "RATS - Rough auditing tool for security") combined with a brief manual inspection are sufficient to identify the low-hanging fruits. However, memory corruption conditions can have complex causes. For example, an use-after-free bugs might be caused by an intricate, counter-intuitive race condition that is not immediately apparent. These bugs are discovered either using dynamic analysis, or by testers that take the time to gain a deep understanding of the program.

##### Buffer and Integer Overflows

The following code snippet shows a simple example for a buffer overflow vulnerability.

```c
 void copyData(char *userId) {  
    char  smallBuffer[10]; // size of 10  
    strcpy(smallBuffer, userId);
 }  
```

- To identify buffer overflows, look for uses of unsafe string functions (strcpy, strcat, str...) and potentially vulnerable programming constructs, such as copying user input into a limited-size buffer. A ['vanilla' buffer overflow might look as follows](https://www.owasp.org/index.php/Reviewing_Code_for_Buffer_Overruns_and_Overflows "OWASP - Reviewing code for buffer overruns and overflows"). The following are examples for unsafe string functions:
    - strcat
    - strlcat
    - strcpy
    - strncat
    - strlcat
    - strncpy
    - strlcpy
    - sprintf
    - snprintf
    - gets

- Look for instances of copy operations implemented as for- and while loops, and verify that length checks are performed correctly;
- When integer variables are used for array indexing, buffer length calculations, or any other security-critical operations, ensure that unsigned integer types are used and precondition tests are performed to prevent the possibility of integer wrapping.

#### Dynamic Analysis

This kind of bug is best discovered using input fuzzing, a black-box software testing technique in which malformed data is repeatedly sent to an application injection, usually in an automated fashion. At the same time, the application is monitored for malfunctions and crashes. If and when crashes occur, the hope (at least for security testers) is that the conditions leading to the crash point to an exploitable security flaw.

Fuzzers typically are used to generate structured inputs in a semi-correct fashion. The idea is to create inputs that are at least partially accepted by the target application, while at the same time containing invalid elements that potentially trigger input processing flaws and unexpected program behaviors. A good fuzzer creates inputs that triggers a large percentage of possible program execution paths (high coverage). Inputs are generated either from scratch ("Generation-based") or by mutation known, valid input data ("mutation-based").

For more information on fuzzing, refer to the [OWASP Fuzzing Guide](https://www.owasp.org/index.php/Fuzzing).

#### Remediation

- Avoid using unsafe string functions such as strcpy, strcat, strncat, strncpy, sprint, vsprintf, gets, and so on.
- If you are using C++, use the ANSI C++ string class.
- If you are writing code in Objective-C, use the NSString class. If you are writing code in C on iOS, you can use CFString, the Core Foundation representation of a string.
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

Cross-site scripting (XSS) flaws enable attackers to inject client-side scripts into web pages viewed by users. This type of flaw is very common in the web applications. If the user views the injected script in their browser, the attacker can bypass the same origin policy and do pretty much everything in the context of vulnerable website (e.g. stealing session cookies, logging key presses, or performing arbitrary actions).

In the context of mobile apps, XSS risks are far less prevalent for the simple reason that mobile apps aren't web browsers. However, apps that use WebView components such as <code>UIWebView</code>on iOS and <code>WebView</code> on Android are potentially vulnerable to attacks.

An older, but well-known example is the [local XSS issue in the Skype app for iOS identified by Phil Purviance](https://superevr.com/blog/2011/xss-in-skype-for-ios "Superevr.com - XSS in Skype for iOS"). The Skype app failed to properly encode the name of the message sender, allowing an attacker to inject malicious JavaScript that would be executed when the user viewed the message. In his proof-of-concept, Phil showed how to exploit the issue to steal the the user's address book.

#### Static Analysis

Take a close look at any Webviews used by an app, and investigate whether any kind of untrusted input is rendered. 

XSS issues may exist if the URL opened by the Webview can be fully or partially controlled. The following example is from an XSS issue in the Zoho Web Service [reported by Linus Särud](https://labs.detectify.com/2015/02/20/finding-an-xss-in-an-html-based-android-application/).

```java
webView.loadUrl("javascript:initialize(" + myNumber + ");");
```

If a Webview is used the to display a remote website, the burden of escaping HTML shifts to the server side. If a server-side stored XSS exists, it can be used to execute script in the context of the Webview. In such a case, it of course makes sense to also perform static analysis of the web application source code.

#### Dynamic Analysis

XSS issues are best tested for using a combination of manual and automatic input fuzzing, i.e. injecting HTML tags and special characters into all available input fields and verifying that the web application either denies the invalid inputs or escapes the HTML meta-characters in its output.

At least for reflected XSS, automated black-box testing works quite well. For example, the [BURP Scanner]() is very effective in identifying those issues. However, as always in automated analysis, you need make sure that all input vectors are covered.

#### Remediation

Security testers commonly use the infamous JavaScript message box to demonstrate exploitation of XSS. Inadvertently, developers sometimes assume that blacklisting the alert() command is an acceptable solution. This couldn't be farther from the truth! Instead, XSS is best prevented by following general programming best practices.

- Don't put untrusted data into your HTML document unless it is necessary, and when you do, be aware of the context in which the data is rendered. Note that escaping rules can get complicated in nested contexts, such as rendering an URL inside a JavaScript block.

- Escape characters with an appropriate encoding, such as HTML entity encoding, to prevent switching into any execution context, such as script, style, or event handlers. 

Make sure that you escape adequately depending on how the data is rendered in the response. For example, there are six control characters in HTML that need escaping:

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
