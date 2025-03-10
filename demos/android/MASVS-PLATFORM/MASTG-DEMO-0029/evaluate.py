import re

def main():
    # Read the output.txt file
    with open("output.txt", "r") as f:
        lines = f.readlines()

    # Initialize defaults according to specification
    js_enabled = False
    content_access = True
    universal_access = False

    # Define regex patterns
    js_pattern = re.compile(r"setJavaScriptEnabled\((true|false)\)", re.IGNORECASE)
    content_pattern = re.compile(r"setAllowContentAccess\((true|false)\)", re.IGNORECASE)
    universal_pattern = re.compile(r"setAllowUniversalAccessFromFileURLs\((true|false)\)", re.IGNORECASE)

    # Iterate over all lines and update our settings if the method call is found
    for line in lines:
        js_match = js_pattern.search(line)
        content_match = content_pattern.search(line)
        universal_match = universal_pattern.search(line)

        if js_match:
            js_enabled = js_match.group(1).lower() == "true"
        elif content_match:
            content_access = content_match.group(1).lower() == "true"
        elif universal_match:
            universal_access = universal_match.group(1).lower() == "true"

    # Test Fails if all of these are true
    if js_enabled and content_access and universal_access:
        print("[FAIL] All insecure settings are enabled.")
    else:
        print("[PASS] At least one secure setting is in place.")

    print(f"  setJavaScriptEnabled: {js_enabled}")
    print(f"  setAllowContentAccess: {content_access}")
    print(f"  setAllowUniversalAccessFromFileURLs: {universal_access}")


if __name__ == "__main__":
    main()