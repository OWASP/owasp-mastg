import re

# Minimum SDK version
MIN_SDK_VERSION = 29

# Default settings based on SDK version
settings = {
    "JavaScriptEnabled": False,
    "AllowFileAccess": MIN_SDK_VERSION < 30,
    "AllowFileAccessFromFileURLs": MIN_SDK_VERSION < 16,
    "AllowUniversalAccessFromFileURLs": MIN_SDK_VERSION < 16
}

# Read and process file line by line
with open("output.txt", "r") as file:
    for line in file:
        for key in settings:
            match = re.search(fr"{key}: (true|false)", line, re.IGNORECASE)
            if match:
                settings[key] = match.group(1).lower() == "true"

# Determine pass/fail status
status = "[FAIL] All necessary insecure settings are enabled." if (
    settings["JavaScriptEnabled"] and settings["AllowFileAccess"] and 
    (settings["AllowFileAccessFromFileURLs"] or settings["AllowUniversalAccessFromFileURLs"])
) else "[PASS] At least one secure setting is in place."

# Write results to evaluation.txt
with open("evaluation.txt", "w") as file:
    file.write(status + "\n")
    for key, value in settings.items():
        file.write(f"  set{key}: {value}\n")
