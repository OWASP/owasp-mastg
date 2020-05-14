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

- Make sure the contributor list in 0x02-Frontispiece.md is up to date with the [contributor scripts](https://github.com/commjoen/contributors-mstg)
- Make sure you have all the files in GIT that you want to release: do not add files to it from another PR, and let the pipeline do its work.
- Make sure you have put the right version everywhere
- Make sure that excels have been updated a priori the release process of a new version. Directly after the release, the actual excel-links can be tested for the new tag set. (so make sure that the new excel links are compatible with the chosen tag in step 3).

Steps:

1. Sync @sushi2k's repository for Gitbook (done automatically now)
2. Update the Changelog.md.
3. Generate new PDF and docx with the new version for review, e.g. version 1.2 (`cd Tools && ./gendocsLocal.sh 1.2`). Files are available in `Generated` folder for verification purpose ONLY.
4. Commit the changes with message `"Release <version>"` (`$ git commit -m "Release 1.2"`). Then push it to a release branch, make sure it gets reviewed & merged.
5. Push a tag with the new version (`git checkout master && git tag -a <version> -m "Release message that will be on github" && git push --tags` )
6. Update the Leanpub Files at Leanpub with the downloaded files from the release page.
7. Update OWASP Wiki if necessary with release news.
8. Update the book at lulu.com (Ask @sushi2k) with the downloaded PDF from the release page.
9. Tweet about it with @OWASP-MSTG & share a message at LinkedIn.
