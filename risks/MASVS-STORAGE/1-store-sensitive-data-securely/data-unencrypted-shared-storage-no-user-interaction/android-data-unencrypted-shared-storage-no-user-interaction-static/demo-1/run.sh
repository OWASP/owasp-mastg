NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml ./MastgTest_reversed.java --text -o output.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-apis.yml ./MastgTest_reversed.java --sarif -o output.sarif

NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml ./AndroidManifest_reversed.xml --text -o output2.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-shared-storage-no-user-interaction-manifest.yml ./AndroidManifest_reversed.xml --sarif -o output2.sarif
