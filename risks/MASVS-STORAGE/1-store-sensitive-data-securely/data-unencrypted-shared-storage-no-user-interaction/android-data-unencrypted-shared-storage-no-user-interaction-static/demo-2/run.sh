NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./AndroidManifest_reversed.xml --text -o output.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./AndroidManifest_reversed.xml --sarif -o output.sarif
