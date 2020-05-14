# Tools

## Overview

This directory is for tools that are used to generate the necessary files for our release-channels.

## Channels

- Gitbook: currenlty using @sushi2k's repository which is synced manually.
- Github release: currently using travis to automatically build stuff based on a tag. See ../travis.yml. It uses `gendocs.sh`, `generate_document.sh` and `gitbookepubanpdf.sh`.
- Leanpub: `updateLeanpub.sh` is in the making: for now it contains only instructions.

## Files

- Apply_Link_Check.sh: used to check whether there are any broken links in the markdown files. Requires `markdown-link-check` to be installed.
- Apply_Linter_Check.sh: used to check whether there are any markdown markup issues. Requires `markdownlint-cli` to be installed.
- before_install.sh: script used by the Travis pipeline to check which tools need to be installed depending on whether it is a pull-request or a tag has been added for a release.
- book.json: the book.json metadata template for Gitbook. Necessary for `gitbookepubanpdf.sh` to automatically create an updated book.json in the root of the folder.
- gendocs.sh: used to simplify the work with Travis.
- gendocsLocal.sh: used to simplify the work with Travis, but then on your local machine (partially).
- generate_document.sh: used to generate the docx and html files.
- generate_toc.rb: used to generate a TOC file.
- gitbookepubandpdf.sh: used to generate the epub, pdf and mobi files.
- metadata.yml: used by pandoc for generating docx files with `generate_Document.sh`.
- omtg-pre-commit.sh: older not maintained hook for automatically triggering `generate_toc.rb`.
- reference.docx: templatefile used for generating the word doc using `generate_document.sh`.

## Release process

Pre-checks:

- make sure the contributor list is up to date with the [contributor scripts](https://github.com/commjoen/contributors-mstg)
- make sure you have all the files in GIT that you want to release: do not add files to it from another PR.
- make sure you have put the right version everywhere

Steps:

1. Sync @sushi2k's repository for Gitbook (done automatically now)
2. Update the Changelog.md.
3. Generate new PDF with the new version for review.
4. Commit the changes (with message `"Release <version>"`)
5. Push a tag with the new version (`git tag -a <version> -m "Release message that will be on github"`)
6. Update the Leanpub Files at Leanpub
7. Update OWASP Wiki if necessary
8. Update the book at lulu.com (Ask @sushi2k)
9. Tweet about it with @OWASP-MSTG & share a message at LinkedIn.
