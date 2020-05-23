#!/bin/bash
# Script taken from https://github.com/OWASP/CheatSheetSeries/blob/master/scripts/Apply_Linter_Check.sh
# Script in charge of auditing the released MD files with the linter policy defined at project level

cd ../
if test -f "linter-result.out"; then
        rm linter-result.out
fi
markdownlint -c .markdownlint.json -o linter-result.out Document
errors=`wc -m linter-result.out | cut -d' ' -f1`
content=`cat linter-result.out`
if [[ $errors != "0" ]]
then
    echo "[!] Error(s) found by the Linter: $content"
    exit $errors
else
    echo "[+] No error found by the Linter."
    rm linter-result.out
fi