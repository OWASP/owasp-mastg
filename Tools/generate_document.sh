#!/bin/bash
type pandoc >/dev/null 2>&1 || { echo >&2 "I require pandoc but it's not installed.  Aborting."; exit 1; }
# How to generate Docx
cd Document
pandoc -f markdown_github --columns 10000 -t docx -o ../MSTG.docx *.md Testcases/*.md
pandoc -f markdown_github --columns 10000 -t html -o ../MSTG.html *.md Testcases/*.md
