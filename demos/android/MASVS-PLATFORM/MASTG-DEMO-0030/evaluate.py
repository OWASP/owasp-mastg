import re

def main():
    # Default values
    settings = {
        "JavaScriptEnabled": False,
        "AllowContentAccess": True,
        "AllowUniversalAccessFromFileURLs": False
    }

    # Read and process file line by line
    with open("output.txt", "r") as file:
        for line in file:
            for key in settings:
                match = re.search(fr"{key}: (true|false)", line, re.IGNORECASE)
                if match:
                    settings[key] = match.group(1).lower() == "true"

    # Determine pass/fail status
    status = "[FAIL] All insecure settings are enabled." if all(settings.values()) else "[PASS] At least one secure setting is in place."

    # Write results to evaluation.txt
    with open("evaluation.txt", "w") as output_file:
        output_file.write(status + "\n")
        for key, value in settings.items():
            output_file.write(f"  {key}: {value}\n")

if __name__ == "__main__":
    main()
