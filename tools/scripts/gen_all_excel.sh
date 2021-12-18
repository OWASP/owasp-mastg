#!/bin/bash
echo $PWD
LanguageArray=("de" "en" "es" "fa" "fr" "hi" "ja" "ko" "ru" "zhcn" "zhtw")
for lang in ${LanguageArray[*]}; do
    cd owasp-masvs/tools && python3 ./export.py -f yaml -l $lang > masvs_$lang.yaml && cd -
    python3 parse_html.py -m owasp-masvs/tools/masvs_$lang.yaml -i generated/html -o masvs_full_$lang.yaml
    python3 yaml_to_excel.py -m masvs_full_$lang.yaml -o checklist_$lang.xlsx --mstgversion $1 --mstgcommit $2 --masvsversion $3 --masvscommit $4
done
