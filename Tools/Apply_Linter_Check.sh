#!/bin/bash
# Script taken from https://github.com/OWASP/CheatSheetSeries/blob/master/scripts/Apply_Linter_Check.sh
# Script in charge of auditing the released MD files with the linter policy defined at project level

cd ..
rm linter-result.out
markdownlint -c .markdownlint.json -o linter-result.out Document
errors=`wc -m linter-result.out | cut -d' ' -f1`
content=`cat linter-result.out`
if [[ $errors != "0" ]]
then
    echo "[!] Error(s) found by the Linter: $content"
    echo "Only warning for now..."
    #exit $errors
else
    echo "[+] No error found by the Linter."
fi