NO_COLOR=true semgrep -c ../../../../rules/mastg-android-device-access-security-passcode.yml ./MastgTest_reversed.java --text -o output_passcode.txt
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-device-access-security-sdk-version.yml ./MastgTest_reversed.java --text -o output_version.txt
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-device-access-security-debuggable-system.yml ./MastgTest_reversed.java --text -o output_debuggable_system.txt
