# Exporting the MASVS and the MSTG

## Overview

The `tools/` directory contains scripts that are used to export the MASVS and the MSTG in different formats ready to be released. This includes both document (PDF, Word, etc.) and machine readable formats (yaml, csv, etc.).

## Export the Documents

The MASVS and MSTG document generation is based on [pandocker](https://github.com/dalibo/pandocker/).

Each time you push to GitHub, the workflows in the MASVS/MSTG GitHub Actions will be triggered. You can check what will be executed inside the folder `.github/workflows`.

The workflow `docgenerator.yml` runs the `pandoc_makedocs.sh` generation script (for the MASVS, once per language). The results of each execution can be inspected live in: <https://github.com/OWASP/owasp-masvs/actions> and <https://github.com/OWASP/owasp-mstg/actions>

> The generation scripts are in continuous improvement and are tracked here: [https://github.com/OWASP/owasp-masvs/issues/361](https://github.com/OWASP/owasp-masvs/issues/361).

### Internals

The MASVS and MSTG PDFs are generated using the `pandoc_makedocs.sh` script which depends on:

- cover.tex
- first_page.tex
- latex-header.tex
- reference.docx: Template file used for generating the MS Word document.

### How to run it on your Machine

This is completely optional, but it can help debugging some issues.

> Currently not working on Apple Silicon devices (e.g. MacBook M1).

- Install Docker
- `cd` to the MASVS/MSTG root folder (`owasp-masvs/` / `owasp-mstg/`)
- Run the `pandoc_makedocs.sh` script with the language folder and an optional version number (**do not `cd` into `tools/docker` to run it**):

```sh
./tools/docker/pandoc_makedocs.sh Document 1.4.1
```

### Notes

- For non-european languages (Hindi, Persian, CJK, etc.) you need to use the `stable-full` version of the docker image. Define the `TAG` variable like this:

```sh
TAG=stable-full ./tools/docker/pandoc_makedocs.sh Document-ja 1.4.1
```

- You can set `VERBOSE=1` for a more detailed output
- The size `stable-full` docker image is approx. 800MB whereas the regular `stable` version is 330MB.

## Export Machine Readable Formats

### MASVS

The MASVS has the script export.py (uses masvs.py) that can be used to generate a YAML, CSV, JSON or XML version of the MASVS.

Example for exporting a YAML file including the MASVS in Japanese.

```bash
cd owasp-masvs/tools && python3 ./export.py -f yaml -l ja > masvs_ja.yaml
```
