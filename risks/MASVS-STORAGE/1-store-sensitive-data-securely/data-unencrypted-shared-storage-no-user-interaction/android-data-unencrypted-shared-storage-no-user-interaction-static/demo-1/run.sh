NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./MastgTest_reversed.java --text -o output.txt
NO_COLOR=true semgrep -c ../rules/mastg-android-data-unencrypted-external.yml ./MastgTest_reversed.java --sarif -o output.sarif
