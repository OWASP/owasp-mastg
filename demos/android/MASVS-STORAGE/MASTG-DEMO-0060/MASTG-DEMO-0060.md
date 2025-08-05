---
platform: android
title: App Writing Sensitive Data to Sandbox using EncryptedSharedPreferences
id: MASTG-DEMO-0060
code: [kotlin]
test: MASTG-TEST-0287
kind: pass
note: This demo shows how to store sensitive data securely in the app sandbox using the EncryptedSharedPreferences class.
---

### Sample

The following Kotlin code demonstrates how to securely store sensitive data (such as a password and API key) in the app sandbox using `EncryptedSharedPreferences`:

{{ MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C` and/or `q` to quit the Frida CLI

{{ hooks.js # run.sh }}

### Observation

The output shows all instances of strings written using `EncryptedSharedPreferences` via `SharedPreferences` that were found at runtime. A backtrace is also provided to help identify the location in the code.

{{ output.json }}

### Evaluation

This test **passes** because sensitive data is stored using `EncryptedSharedPreferences`, which encrypts both keys and values at rest. Even if an attacker gains access to the app's sandbox, the data remains protected and unreadable without the app's encryption keys.

For example, to confirm this, run the following command:

```sh
adb shell cat /data/data/org.owasp.mastestapp/shared_prefs/MasSharedPref_Sensitive_Data.xml
```

Which returns:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <set name="preSharedKeys">
        <string>gJXS9EwpuzK8U1TOgfplwfKEVngCE2D5FNBQWvNmuHHbigmTCabsA=</string>
        <string>MIIEvAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfX7kbfFv3pc3JjOHQ=</string>
    </set>
    <string name="EncryptedAWSKey">pxEiQP+VKpawU4B4fLoxk6v85z5UKXsYAq64lwUKL3ZBu3y7Ab+qTyGlXrZcqKzW&#10;    </string>
    <string name="__androidx_security_crypto_encrypted_prefs_key_keyset__">12a901eca02edb449ca6eff4c578f9a952c35a...</string>
    <string name="AUL3Px4pwXPb6gLG5OX48h5nKeBAKRGf616ybiTzcYI=">ARuZb6AqdljdJ7L9CUayBeSEC0SliQ2AoW3V+9oirzIc0mJdfGUfZY2kM7KGGhHt/5PLe6rNoAHVEFxSckoErV8RWQcGCTb6uif0pUU=</string>
    <string name="AUL3Px64PpFLIrZk+ZdSewnmsZAM5xjKhDRTOBb/0UlYMw==">ARuZb6DkkPCUF6z5qtDS83z+Toe60jSAYf+XM/n4tSPeICmlUfV5MFqNuO5ONIxOTdTgNs18+ET+fIrBOQ9iiLhyGokjWvsFp6MiceP//fXWIIfCQJGgEAFfGiOLO+7FDqucemQP0laysVWvahhHYcw6Wbk424Uqo2lxFSe/kTfZI+/QJ0mCKOGxXEfaHQAsUqdOqpKxppsMxO3hzKDc5fN3ew1QX3E=</string>
    <string name="__androidx_security_crypto_encrypted_prefs_value_keyset__">128801630b7bbf51cb1c0dbd7b76d881ccd9...</string>
    <string name="GitHubToken">FtZv5Zl5ULTonWZFr9vH1q8vuH9VtZAe0qQLZS4GhwGjXmLU1G+U+GsghU2JzeRSdXKfo+MeV2uZ&#10;/EJ5t0bGpA==&#10;    </string>
    <string name="AUL3Px45SzM2kV7WxPAT6C/+pC+qCdFnO+cjU/2Cv5vVZa4F">ARuZb6DQ3VIUnc+1gD3isLliTFCSh8SKiq+fbWUYEKCZ7/qjnP7ukVckwr2NEdm1i4qXCw/njxBsgowH/g==</string>
</map>
```

The actual values are not visible in plain text, confirming that encryption is applied.
