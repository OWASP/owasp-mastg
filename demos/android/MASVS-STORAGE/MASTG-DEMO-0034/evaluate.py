import re

FAIL_MESSAGE = "[FAIL] Backup is enabled"
PASS_MESSAGE = "[PASS] Backup is disabled"

def main():
    # Default settings
    settings = {
        "android:allowBackup": False,
    }

    # Read and process file line by line
    with open("output.txt", "r") as file:
        for line in file:
            for key in settings:
                match = re.search(fr"{key}=(\"true\"|\"false\")", line, re.IGNORECASE)
                if match:
                    settings[key] = match.group(1).lower() == "true"

    # Determine pass/fail status
    status = FAIL_MESSAGE if settings["android:allowBackup"] else PASS_MESSAGE

    # Write results to evaluation.txt
    with open("evaluation.txt", "w") as file:
        file.write(status + "\n")
        for key, value in settings.items():
            file.write(f"  {key}: {value}\n")

if __name__ == "__main__":
    main()