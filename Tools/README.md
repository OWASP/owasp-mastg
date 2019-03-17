# Tools

## Overview

This directory is for tools that are used to generate the necessary files for our release-channels.

Channels:
- Gitbook: currenlty using @sushi2k's repository which is synced manually.
- Github release: currently using travis to automatically build stuff based on a tag. See ../travis.yml. It uses `gendocs.sh`, `generate_document.sh` and `gitbookepubanpdf.sh`.
- Leanpub: `updateLeanpub.sh` is in the making: for now it contains only instructions.

Files:
- book.json: the book.json metadata template for Gitbook. Necessary for `gitbookepubanpdf.sh` to automatically create an updated book.json in the root of the folder.
- gendocs.sh: used to simplify the work with Travis.
- generate_document.sh: used to generate the docx and html files.
- generate_toc.rb: used to generate a TOC file.
- gitbookepubandpdf.sh: used to generate the epub, pdf and mobi files.
- metadata.yml: used by pandoc for generating docx files with `generate_Document.sh`.
- omtg-pre-commit.sh: older not maintained hook for automatically triggering `generate_toc.rb`.
- reference.docx: templatefile used for generating the word doc using `generate_document.sh`.

## Release process:
1. Sync @sushi2k's repository
2. Update the Changelog.md
3. Commit the changes (with message "Release <version>")
4. Push a tag with the new version (git tag -a <version> -m "Release message that will be on github")
5. Update the Leanpub Files at Leanpub
6. Update OWASP Wiki if necessary
7. Update the book at lulu.com (Ask @sushi2k)
8. Tweet about it with @OWASP-MSTG.
