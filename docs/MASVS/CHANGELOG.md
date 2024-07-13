# Changelog

## V1.3.1 and newer

All our Changelogs are available online at the OWASP MASVS GitHub repository, see the [Releases page](https://github.com/OWASP/owasp-masvs/releases).

## V1.3 - 13 May 2021

We are proud to announce the introduction of a new document build pipeline, which is a major milestone for our project. The build pipeline is based on [Pandocker](https://github.com/dalibo/pandocker) and [Github Actions](https://github.com/OWASP/owasp-masvs/tree/master/.github/workflows).
This significantly reduces the time spent on creating new releases and will also be the foundation for the OWASP MSTG and will be made available for the OWASP ASVS project.

### Changes

- 4 more translations are available, which are Hindi, Farsi, Portuguese and Brazilian Portuguese
- Added requirement MSTG-PLATFORM-11

### Special Thanks

- Jeroen Willemsen for kick-starting this initiative last year!
- Damien Clochard and Dalibo for supporting and professionalizing the build pipeline.
- All our Hindi, Farsi, Portuguese and Brazilian Portuguese collaborators for the excellent translation work.

## V1.2 - 7 March 2020 - International Release

The following changes are part of release 1.2:

- Translation in simplified Chinese of the MASVS available.
- Change of title in MASVS book cover.
- Removed Mobile Top 10 and CWE from MSTG and merged to existing references in MASVS.

## V1.2-RC - 5 October 2019 - Pre-release (English only)

The following changes are part of pre-release 1.2:

- Promoted to flagship status.
- Requirement changed: MSTG-STORAGE-1 "need to be used".
- Requirements MSTG-STORAGE-13, MSTG-STORAGE-14, and MSTG-STORAGE-15 are added with a focus on data protection.
- Requirement MSTG-AUTH-11 is updated to preserve contextual information.
- Requirement MSTG-CODE-4 is updated to cover more than just debugging.
- Requirement MSTG-PLATFORM-10 added to further secure usage of WebViews.
- Requirement MSTG-AUTH-12 added to remind developers of having authorizations implemented, especially in case of multi-user apps.
- Added a little more description on how the MASVS should be used given a risk assessment.
- Added a little more description on paid content.
- Requirement MSTG-ARCH-11 added to include a Responsible Disclosure policy for L2 applications.
- Requirement MSTG-ARCH-12 added to show application developers that relevant international privacy laws should be followed.
- Created a consistent style for all references in the English version.
- Requirement MSTG-PLATFORM-11 added to counter spying via third party keyboards.
- Requirement MSTG-MSTG-RESILIENCE-13 added to impede eavesdropping at an application.

## V1.1.4 - 4 July 2019 - Summit edition

The following changes are part of release 1.1.4:

- Fix all markdown issues.
- Updates in the French and Spanish translations.
- Translated the changelog to Chinese (ZHTW) and Japanese.
- Automated verification of the the markdown syntax and reachability of the URLs.
- Added identification codes to the requirements, which will be included in the future version of the MSTG in order to find the recommendations and testcases easily.
- Reduced the repo size and added Generated to the .gitignore.
- Added a Code of Conduct & Contributing guidelines.
- Added a Pull-Request template.
- Updated the sync with the repo in use for hosting the Gitbook website.
- Updated the scripts to generate XML/JSON/CSV for all the translations.
- Translated the Foreword to Chinese (ZHTW).

## V1.1.3 - 9 January 2019 - Small fixes

- Fix translation issue of requirement 7.1 in the Spanish version
- New setup of translators in acknowledgements

## V1.1.2 - 3 January 2019 - Sponsorship and internationalization

The following changes are part of release 1.1.2:

- Added thank you note for buyers of the e-book.
- Added missing authentication link & updated broken authentication link in V4.
- Fixed swap of 4.7 and 4.8 in English.
- First international release!
  - Fixes in Spanish translation. Translation is now in sync with English (1.1.2).
  - Fixes in Russian translation. Translation is now in sync with English (1.1.2).
  - Added first release of Chinese (ZHTW) French, German, and Japanese!
- Simplified document for ease of translation.
- Added instructions for automated releases.

## V1.1.0 - 14 July 2018

The following changes are part of release 1.1:

- Requirement 2.6 "The clipboard is deactivated on text fields that may contain sensitive data." was removed.
- Requirement 2.2 "No sensitive data should be stored outside of the app container or system credential storage facilities." was added.
- Requirement 2.1 was reworded to "System credential storage facilities are used appropriately to store sensitive data, such as PII, user credentials or cryptographic keys.".

## V1.0 12 - January 2018

The following changes are part of release 1.0:

- Delete 8.9 as the same as 8.12
- Made 4.6 more generic
- Minor fixes (typos etc.)
