NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./use-of-external-store.kt --text -o output.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./use-of-external-store.kt --sarif -o output.sarif
