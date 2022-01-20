#!/bin/bash
echo $PWD
LanguageArray=( $(ls -1 | grep Document | sed -r 's/Document-?//g' | sed 's/^$/en/g' | tr '\n' ' ') )
for lang in ${LanguageArray[*]}; do
    echo lang
done
    cd owasp-masvs/tools && python3 ./export.py -f yaml -l $lang > masvs_$lang.yaml && cd -
    python3 parse_html.py -m owasp-masvs/tools/masvs_$lang.yaml -i generated/html -o masvs_full_$lang.yaml
    python3 yaml_to_excel.py -m masvs_full_$lang.yaml -o Mobile_App_Security_Checklist_$lang.xlsx --mstgversion $1 --mstgcommit $2 --masvsversion $3 --masvscommit $4
done
