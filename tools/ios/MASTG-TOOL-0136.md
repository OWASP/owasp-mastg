---
title: plistlib
platform: ios
host:
- macOS
- windows
- linux
---

The [plistlib module](https://docs.python.org/3/library/plistlib.html) is part of the Python standard library and allows you to programmatically read, modify, and write `.plist` (Property List) files. It supports both XML and binary plist formats and provides a native dictionary-based API.

This makes `plistlib` a cross-platform alternative to @MASTG-TOOL-0135, suitable for scripting or automation use cases.

## Reading a Plist File

The following example prints the contents of a plist file by loading it into a Python dictionary:

```python
import plistlib

with open("Info.plist", "rb") as f:
    plist = plistlib.load(f)

print(plist)
```

This prints a dictionary representation of the plist, which can be inspected and modified like any other Python dict.

## Reading Specific Plist Entries

After parsing the plist, you can access dictionary keys and array elements using regular Python syntax. The example below prints the third app icon format:

```python
print(plist["CFBundleIcons~ipad"]["CFBundlePrimaryIcon"]["CFBundleIconFiles"][2])
# Output: AppIcon-140x40
```

## Changing Plist Values

To modify an entry such as the `CFBundleDisplayName`, assign a new value and write the updated dict back to the file using `plistlib.dump`:

```python
plist["CFBundleDisplayName"] = "My New App Name"

with open("Info.plist", "wb") as f:
    plistlib.dump(plist, f)
```

## Adding and Deleting Plist Values

New keys can be added or removed using regular Python dict operations:

```python
# Add a new dictionary
plist["CustomDictionary"] = {"CustomProperty": "OWASP MAS"}

# Delete a key
del plist["CustomDictionary"]["CustomProperty"]

# Save the updated plist
with open("Info.plist", "wb") as f:
    plistlib.dump(plist, f)
```
