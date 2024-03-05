NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external-manifest.yml ./AndroidManifest.xml --text -o output.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external-manifest.yml ./AndroidManifest.xml --sarif -o output.sarif
