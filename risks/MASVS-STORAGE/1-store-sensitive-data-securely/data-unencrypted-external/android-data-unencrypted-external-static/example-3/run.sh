NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./use-of-mediastore.kt --text -o output.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./use-of-mediastore.kt --sarif -o output.sarif
