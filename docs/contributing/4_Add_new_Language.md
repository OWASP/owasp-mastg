# Add a New Language

## MASTG Translations

The MASTG is a living document that changes and adapts to the most recent security recommendations every day. While we do want to reach the maximum audience possible, our past experience shows that **maintaining translations has proven to be an extremely challenging task**. Therefore, please understand that **any PRs containing MASTG translations will be declined**, but you're free to do them on your own forks.

> 🇯🇵 A translation of the MASTG into Japanese is available on Github: <https://github.com/coky-t/owasp-mstg-ja>. Thanks to @coky-t for pushing this forward!

That said, we **strongly encourage further translations of the MASVS as it is much easier to maintain and you'll get a translated [Mobile App Security Checklists](https://github.com/OWASP/owasp-mastg/releases/latest) mapping to the MASTG for free.

## MASVS Translations

To add a new language you have to follow the steps from both sections below.

1. Create a folder with the language of choice, e.g. `Document-ja`.
2. Copy an existing `metadata.md` from another language and modify it for the new language.
3. Add the language to the list of languages in `export.py`
4. Update `.github/workflows/docgenerator.yml` and add the action steps for the new language.
5. Update `../LANGS.md` to include the new language.
6. Extend the `../README.md` with the newly available language.
7. Release the MASVS.

## In the MASTG

IMPORTANT: only after releasing the MASVS!

1. Add the new language to `tools/scripts/gen_all_excel.sh`.
2. Push and verify that the new Checklist is correctly generated for the new language.
