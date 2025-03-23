---
masvs_v1_id:
- MSTG-PLATFORM-2
masvs_v2_id:
- MASVS-CODE-4
platform: android
title: Testing for Injection Flaws
masvs_v1_levels:
- L1
- L2
type: [static, dynamic]
available_since: 21
deprecated_since: 29
weakness: 
- MASWE-9
- CWE-89
---

## Overview

Injection flaws occur when an application processes **untrusted input** in a way that allows an attacker to **manipulate queries, execute unintended commands, or inject malicious code**. These vulnerabilities can lead to **data leaks, privilege escalation, or remote code execution**.

In Android applications, injection flaws are often found in:

- **SQL Queries** (SQL Injection)
- **Command Execution Functions** (Command Injection)
- **Inter-Process Communication (IPC) Mechanisms** (Intent Injection, ContentProvider exploitation)
- **Web-based Components** (WebView JavaScript Injection)

This test ensures that **all input sources are properly sanitized and validated** to prevent injection attacks.

### Pre-requisites

- Use **Frida, Burp Suite, or Drozer** for dynamic testing.
- Test on **Android 10+** to account for security changes (e.g., Scoped Storage).
- Review the **MASVS-CODE-4** section in the OWASP MASVS documentation.
- Understand secure coding practices for input validation and query sanitization.

## Static Analysis

### Identifying Injection Vulnerabilities in Code

Injection flaws often occur when **user input is directly concatenated** into SQL queries, system commands, or IPC mechanisms. The following areas should be examined in static analysis:

1. **Database Queries (SQL Injection)**
2. **Command Execution Functions (Command Injection)**
3. **Inter-Process Communication (IPC) Exposure (Intent Injection, ContentProvider Exploits)**
4. **WebView Misuse (JavaScript Injection)**

### Example: SQL Injection via `ContentProvider`

A common vulnerable IPC mechanism in Android is an **exported ContentProvider** that allows other apps to access a database. The following **incorrect implementation** is prone to SQL Injection:

#### Vulnerable Code

```xml
<provider
    android:name=".VulnerableContentProvider"
    android:authorities="com.example.vulnerable.provider"
    android:exported="true">
</provider>
```

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("students");

    switch (uriMatcher.match(uri)) {
        case STUDENTS:
            break;

        case STUDENT_ID:
            // UNSAFE: Directly appending user input to SQL query
            qb.appendWhere("_id = " + uri.getPathSegments().get(1));
            break;

        default:
            throw new IllegalArgumentException("Unknown URI " + uri);
    }

    return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder);
}
```

#### Why is this code vulnerable?

- It concatenates user input (uri.getPathSegments().get(1)) directly into an SQL query.
- An attacker can inject malicious SQL code via the URI path, leading to SQL Injection attacks.
- If exploited, an attacker can steal, modify, or delete data from the database.

#### Secure Implementation

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection, String selectionArgs[], String sortOrder) {
    SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
    qb.setTables("students");

    switch (uriMatcher.match(uri)) {
        case STUDENTS:
            break;

        case STUDENT_ID:
            // SAFE: Using parameterized query to prevent SQL Injection
            qb.appendWhere("_id = ?");
            selectionArgs = new String[]{uri.getLastPathSegment()};
            break;

        default:
            throw new IllegalArgumentException("Unknown URI " + uri);
    }

    return qb.query(db, projection, selection, selectionArgs, null, null, sortOrder);
}
```

## Dynamic Analysis

### Testing for Injection Flaws in a Running Application

While static analysis helps identify potential injection vulnerabilities, dynamic testing allows you to **exploit and confirm** them in a running application.

### Testing for SQL Injection using `adb shell`

If an Android application exposes a vulnerable `ContentProvider`, you can **query it manually** from the command line.

#### Step 1: Check for Exposed Content Providers

Run the following command to list exported ContentProviders:

```bash
adb shell content providers
```

#### Step 2: Query the ContentProvider for Student Data

```bash
adb shell content query --uri content://com.example.vulnerable.provider/students
```

#### Step 3: Attempt SQL Injection

```bash
adb shell content query --uri content://com.example.vulnerable.provider/students --where "name='Bob' OR 1=1--"
```

### Exploiting SQL Injection using Frida

Frida is a powerful tool for **runtime manipulation of Android apps**. You can use it to **hook and modify** database queries.

#### Step 1: Attach to the Target Application

```bash
frida -U -n com.example.vulnerable.app -e "console.log('Frida attached!')"
```

#### Step 2: Intercept and Modify the Query

```javascript
Java.perform(function() {
    var ContentProvider = Java.use("com.example.vulnerable.VulnerableContentProvider");
    ContentProvider.query.implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        console.log("Intercepted query: " + selection);
        return this.query(uri, projection, "1=1--", selectionArgs, sortOrder);
    };
});
```

## References

- [OWASP Mobile Top 10 - M7: Client Code Quality](https://owasp.org/www-project-mobile-top-10/ "OWASP Mobile Top 10")
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html "CWE-89")
- [SQL Injection Cheat Sheet](https://www.websec.ca/kb/sql_injection "SQL Injection Cheat Sheet")
