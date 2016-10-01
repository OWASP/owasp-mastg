#!/bin/bash
type pandoc >/dev/null 2>&1 || { echo >&2 "I require pandoc but it's not installed.  Aborting."; exit 1; }
# How to generate Docx
pandoc -f markdown -t docx -o MASVS.docx Document/*.md
# how to generate pdf
#pandoc --latex-engine=xelatex -o MASVS.pdf Document/*.md