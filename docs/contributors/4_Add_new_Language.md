# Add a New Language

To add a new language you have to follow the steps from both sections below.

## In the MASVS

1. Create a folder with the language of choice, e.g. `Document-ja`.
2. Copy an existing `metadata.md` from another language and modify it for the new language.
3. Add the language to the list of languages in `export.py`
4. Update `.github/workflows/docgenerator.yml` and add the action steps for the new language.
5. Update `../LANGS.md` to include the new language.
6. Extend the `../README.md` with the newly available language.
7. Release the MASVS.

## In the MSTG

IMPORTANT: only after releasing the MASVS!

1. Add the new language to `tools/scripts/gen_all_excel.sh`.
2. Push and verify that the new Checklist is correctly generated for the new language.