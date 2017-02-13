#!/bin/bash
type pandoc >/dev/null 2>&1 || { echo >&2 "I require pandoc but it's not installed.  Aborting."; exit 1; }
# How to generate Docx
cd ../Document
pandoc -f markdown_github --columns 10000 -t docx -o ../Generated/MSTG.docx 0x00-Header.md Foreword.md 0x02-Frontispiece.md 0x03-Overview.md 0x04-Testing-Processes-and-Techniques.md 0x05*.md 0x06*.md 0x07-Security-Testing-SDLC.md 0x08-Testing-Tools.md 0x09-Suggested-Reading.md
pandoc -f markdown_github --columns 10000 -t html -o ../Generated/MSTG.html 0x00-Header.md Foreword.md 0x02-Frontispiece.md 0x03-Overview.md 0x04-Testing-Processes-and-Techniques.md 0x05*.md 0x06*.md 0x07-Security-Testing-SDLC.md 0x08-Testing-Tools.md 0x09-Suggested-Reading.md
