---
title: Static Analysis on Android
platform: android
---

Static analysis is a technique used to examine and evaluate the source code of a mobile application without executing it. This method is instrumental in identifying potential security vulnerabilities, coding errors, and compliance issues. Static analysis tools can scan the entire codebase automatically, making them a valuable asset for developers and security auditors.

Two good examples of static analysis tools are grep and @MASTG-TOOL-0110. However, there are many other tools available, and you should choose the one that best fits your needs.

## Example: Using grep for Manifest Analysis in Android Apps

One simple yet effective use of static analysis is using the `grep` command-line tool to inspect the `AndroidManifest.xml` file of an Android app. For example, you can extract the minimum SDK version (which indicates the lowest version of Android the app supports) with the following `grep` command:

```bash
grep 'android:minSdkVersion' AndroidManifest.xml
```

This command searches for the `android:minSdkVersion` attribute within the manifest file. Ensuring a higher `minSdkVersion` can reduce security risks, as older versions of Android may not include the latest security features and fixes.

## Example: Using semgrep for Identifying Seeds With Insufficient Entropy

semgrep is a more advanced tool that can be used for pattern matching in code. It's particularly useful for identifying complex coding patterns that might lead to security vulnerabilities. For example, to find instances where a deterministic seed is used with the `SecureRandom` class (which can compromise the randomness and thus the security), you can use a semgrep rule like:

```yaml
rules:
  - id: insecure-securerandom-seed
    patterns:
      - pattern: new SecureRandom($SEED)
      - pattern-not: $SEED = null
    message: "Using a deterministic seed with SecureRandom. Consider using a more secure seed."
    languages: [java]
    severity: WARNING
```

This rule will flag any instances in the code where `SecureRandom` is initialized with a specific seed, excluding cases where the seed is null (which implies a secure random seed).
