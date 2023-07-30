#!/bin/bash
# Script taken from https://github.com/OWASP/CheatSheetSeries/blob/master/scripts/Apply_Link_Check.sh
# Script in charge of auditing the released MD files in order to detect dead links

cd ../Document
if test -f "../link-check-result.out"; then
        rm ../link-check-result.out
fi
find . -name \*.md -exec markdown-link-check -q -c ../.github/workflows/config/mlc_config.json {} \; 1>../link-check-result.out 2>&1
errors=`grep -c "ERROR:" ../link-check-result.out`
content=`cat ../link-check-result.out`
if [[ $errors != "0" ]]
then
    echo "[!] Error(s) found by the Links validator: $errors pages have dead links! Verbose output in /link-check-result.out"
    exit $errors
else
    echo "[+] No error found by the Links validator."
    rm ../link-check-result.out
fi
