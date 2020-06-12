#!/bin/bash
type pandoc >/dev/null 2>&1 || { echo >&2 "I require pandoc but it's not installed.  Aborting."; exit 1; }
# How to generate Docx
# TODO for later releases:
# 0. fix position of TOC: https://stackoverflow.com/questions/25591517/pandoc-inserting-pages-before-generated-table-of-contents
# 1. add changelog
# 2. add [DATE] to tag+tag of Date

cd ../Document
# ../tools/metadata.yml \
pandoc -f gfm --toc -N --columns 10000 --self-contained -s --reference-doc ../tools/reference.docx -t docx  -o ../Generated/MSTG-EN.docx \
# 0x00-Header.md \
Foreword.md \
0x02-Frontispiece.md \
0x03-Overview.md \
0x04-General-Testing-Guide.md \
0x04a-Mobile-App-Taxonomy.md \
0x04b-Mobile-App-Security-Testing.md \
0x04c-Tampering-and-Reverse-Engineering.md \
0x04e-Testing-Authentication-and-Session-Management.md \
0x04f-Testing-Network-Communication.md \
0x04g-Testing-Cryptography.md \
0x04h-Testing-Code-Quality.md \
0x04i-Testing-user-interaction.md \
0x05-Android-Testing-Guide.md \
0x05a-Platform-Overview.md \
0x05b-Basic-Security_Testing.md \
0x05d-Testing-Data-Storage.md \
0x05e-Testing-Cryptography.md \
0x05f-Testing-Local-Authentication.md \
0x05g-Testing-Network-Communication.md \
0x05h-Testing-Platform-Interaction.md \
0x05i-Testing-Code-Quality-and-Build-Settings.md \
0x05c-Reverse-Engineering-and-Tampering.md \
0x05j-Testing-Resiliency-Against-Reverse-Engineering.md \
0x06-iOS-Testing-Guide.md \
0x06a-Platform-Overview.md \
0x06b-Basic-Security-Testing.md \
0x06d-Testing-Data-Storage.md \
0x06e-Testing-Cryptography.md \
0x06f-Testing-Local-Authentication.md \
0x06g-Testing-Network-Communication.md \
0x06h-Testing-Platform-Interaction.md \
0x06i-Testing-Code-Quality-and-Build-Settings.md \
0x06c-Reverse-Engineering-and-Tampering.md \
0x06j-Testing-Resiliency-Against-Reverse-Engineering.md \
0x07-Appendix.md \
0x08-Testing-Tools.md \
0x09-Suggested-Reading.md \
SUMMARY.md

# cd ../Document-ru
#
# pandoc -f gfm --toc -N --columns 10000 --self-contained --reference-doc ../tools/reference.docx -t docx  -o ../Generated/MSTG_2.docx \
# 0x03-Overview.md \
# 0x04-General-Testing-Guide.md \
# 0x04a-Mobile-App-Taxonomy.md \
# 0x04b-Mobile-App-Security-Testing.md \
# 0x04c-Tampering-and-Reverse-Engineering.md \
# 0x04e-Testing-Authentication-and-Session-Management.md \
# 0x04f-Testing-Network-Communication.md \
# 0x04g-Testing-Cryptography.md \
# 0x04h-Testing-Code-Quality.md \
# 0x05-Android-Testing-Guide.md \
# 0x05a-Platform-Overview.md \
# 0x05b-Basic-Security_Testing.md \
# 0x05d-Testing-Data-Storage.md \
# 0x05e-Testing-Cryptography.md \
# 0x05f-Testing-Local-Authentication.md \
# 0x05g-Testing-Network-Communication.md \
# 0x05h-Testing-Platform-Interaction.md \
# 0x05i-Testing-Code-Quality-and-Build-Settings.md \
# 0x05c-Reverse-Engineering-and-Tampering.md \
# 0x05j-Testing-Resiliency-Against-Reverse-Engineering.md \
# 0x06-iOS-Testing-Guide.md \
# 0x06a-Platform-Overview.md \
# 0x06b-Basic-Security-Testing.md \
# 0x06d-Testing-Data-Storage.md \
# 0x06e-Testing-Cryptography.md \
# 0x06f-Testing-Local-Authentication.md \
# 0x06g-Testing-Network-Communication.md \
# 0x06h-Testing-Platform-Interaction.md \
# 0x06i-Testing-Code-Quality-and-Build-Settings.md \
# 0x06c-Reverse-Engineering-and-Tampering.md \
# 0x06j-Testing-Resiliency-Against-Reverse-Engineering.md \
# 0x07-Appendix.md \
# 0x08-Testing-Tools.md \
# 0x09-Suggested-Reading.md
#
# pandoc -f gfm -N --columns 10000 --reference-doc ../tools/reference.docx -o ../Generated/MSTG_1-ru.docx \
# 0x00-Header.md \
# Foreword.md \
# 0x02-Frontispiece.md
#
# pandoc -f docx -N --columns 10000 --reference-doc ../tools/reference.docx -o ../Generated/MSTG-ru.docx \
# ../Generated/MSTG_1-ru.docx \
# ../Generated/MSTG_2-ru.docx
