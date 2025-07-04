# shellcheck disable=SC2148
NO_COLOR=true semgrep -c ../../../../rules/mastg-android-custom-intent-filter-intercept.yml ../MASTG-DEMO-0058/AndroidManifest_reversed.xml --text -o output.txt