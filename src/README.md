# Tools (Partially Outdated, double check!)

## Overview

This directory is for tools that are used to generate the necessary files for our release-channels.

Channels:

- Gitbook: currently using @sushi2k's repository (<https://github.com/sushi2k/owasp-mstg-1>) which is synced automatically via <https://github.com/apps/pull>.
- Github actions & Github releases: We use Github actions to build and verify the documents in an automated fashion as well as build releases.
- Leanpub: The book can be bought via Leanpub <https://leanpub.com/owasp-mastg> as PDF to support OWASP and the MAS project financially.
- Lulu: The book can be bought via Lulu <https://www.lulu.com/shop/jeroen-willemsen-and-sven-schleier-and-bernhard-müller-and-carlos-holguera/owasp-mobile-security-testing-guide/paperback/product-1kw4dp4k.html> as hard-copy to support OWASP and the MAS project financially.

Files:

- `Apply_Link_Check.sh`: Tool to inspect the links in the document folders for every language.
- `Apply_Lint_Check.sh`: Tool to inspect the markdown files their markup in the document folders for every language.
- `contributors.py`: Python script to retrieve current contributors and group them into our different categories according to their additions.
- `custom-reference.docx`: Template file used for generating the word document.
- `pandoc_makedocs.sh`: Script that is being used to generate PDF, ePub and docx version of the MASTG. This script can be used to generate the documents locally and is also used in Github Actions.
- `updateLeanpub.sh` is in the making: for now it contains only instructions.

## Release process

1. Update the CHANGELOG.md in the Documents directory and add a release statement and summary of the changes since the last release. Update the RECENT_CHANGES.md in the tools folder. Add it also to the CHANGELOG.md in the root directory.
2. Commit the changes (with message `Release <version>`)
3. Merge the PR into master
4. Checkout master and pull changes:

    ```bash
    $ git checkout master
    $ git pull
    ```

5. Push a tag with the new version:

    ```bash
    $ git tag -a v<version> -m "Release message"
    $ git push origin v<version>
    ```

    > The letter `v` need to be part of the tag name to trigger the release Github action. The tag name will become the version title of the release. The content of the RECENT_CHANGES file will become the body text of the release (be sure it includes the actual title of the release).

6. Verify that Github Action was triggered and successfully completed <https://github.com/OWASP/owasp-mastg/actions>
7. Verify the new release <https://github.com/OWASP/owasp-mastg/releases>
8. Update OWASP Wiki if necessary <https://owasp.org/mas>
9. Update the files at Lulu with the created files from the release page.
10. Update the files at Leanpub with the created files from the release page.
11. Tweet about it with @OWASP_MAS, Linkedin and OWASP Slack

In case something went wrong and we need to remove the release:

1. Delete the tag locally and remotely:

    ```bash
    $ git tag -d <tag>   # delete the tag locally
    $ git push origin :refs/tags/<tag>  # delete the tag remotely
    ```

2. Go to Github release page <https://github.com/OWASP/owasp-masvs/releases>. The release you removed is now in "draft". Click on edit and discard/delete the release.

## Leanpub

There is a publishing API available <https://leanpub.com/help/api>.

As of now (26th July 2021) the API of Leanpub is only available to Pro Customers, which would costs 12.99 USD per month. For now we do it manually at <https://leanpub.com/owasp-mastg/upload>.

## Lulu

Will be created when we have full support from Lulu. For now do it manually at <https://leanpub.com/mobile-security-testing-guide/upload>.

At the moment (26th July 2021) it's only possible to use the API for ordering books, but not releasing a new version, <https://api.lulu.com/docs/#section/Getting-Started/Generate-a-Token>.
