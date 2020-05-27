#!/bin/bash

# NOTE: This script is not meant to be run locally on your machine (e.g. macOS). Docker will run it for you.

set -euo pipefail

FOLDER=$1
VERSION=$2

echo "FOLDER=${FOLDER}"
echo "VERSION=${VERSION}"

# Load the language metadata (env. vars)
. $FOLDER/LANGUAGE-METADATA

OUTPUT_BASE_NAME="OWASP_MSTG-${VERSION}"

# Put all chapters in order and CHANGELOG at the end
CHAPTERS="${FOLDER}/0x*.md ${FOLDER}/CHANGELOG.md"

# Use per-language tmp files for the cover and the first page
# Replace the placeholder {{MSTG-VERSION}} with the given VERSION and {{MSTG-LANGUAGE}} with the given LANGUAGETEXT
sed -e "s/{{MSTG-VERSION}}/$VERSION/g" -e "s/{{MSTG-LANGUAGE}}/$LANGUAGETEXT/g" ./tools/docker/cover.tex > tmp_cover-$LANGUAGE.tex
sed -e "s/{{MSTG-VERSION}}/$VERSION/g" ./tools/docker/first_page.tex > tmp_first_page-$LANGUAGE.tex

# latex-header.tex contains 2 placeholders for "using CJK fonts" and for the language itself: JP,SC,TC,KR (part of the font name)
# The following does the replacement and writes to a tmp file
cp ./tools/docker/latex-header.tex tmp_latex-header-$LANGUAGE.tex

# given that the formats below require markdown images instead of image tags: let's parse the files:
echo "processing image tags and pagebreaks in $FOLDER/0x*.md, using $LANGUAGE"
for FILE in $FOLDER/0x*.md
do
  [ -f temp-$LANGUAGE ] && rm temp-$LANGUAGE
  # sed -f tools/docker/imagereplace.sed -f tools/docker/pagebreakreplace.sed $FILE > temp-$LANGUAGE
  sed -f tools/docker/imagereplace.sed $FILE > temp-$LANGUAGE
  cat temp-$LANGUAGE > $FILE
  [ -f temp-$LANGUAGE ] && rm temp-$LANGUAGE
done

echo "Done processing tags and breaks in $FOLDER"

# --columns 60 -> pandoc will attempt to wrap lines to the column width specified by --columns (default 72). We need it because of ZHCN.
# --toc to create a Table of Contents with the title from the loaded env. vars.
# -H to apply our customizations in the .tex header file
# --include-before-body -> to include the auto-generated cover and first page as the very beginning

echo "Create PDF"
  pandoc --resource-path=.:${FOLDER} \
    --pdf-engine=xelatex --template=eisvogel \
    --columns 72 \
    --highlight-style=tango \
    --toc -V toc-title:"${TOC_TITLE}" --toc-depth=3 \
    --metadata title="OWASP Mobile Security Testing Guide $VERSION" \
    -H tmp_latex-header-$LANGUAGE.tex -V linkcolor:blue \
    --include-before-body tmp_cover-$LANGUAGE.tex --include-before-body tmp_first_page-$LANGUAGE.tex \
    -o ${OUTPUT_BASE_NAME}-${LANGUAGE}.pdf $CHAPTERS \
    --verbose

# echo "create epub"
# pandoc --resource-path=.:${FOLDER} \
#     -f markdown \
#     -t epub \
#     --metadata title="OWASP Mobile Security Testing Guide" \
#     --metadata lang="${LANGUAGE}" \
#     --metadata author="Bernhard Mueller, Sven Schleier, Jeroen Willemsen, and Carlos Holguera" \
#     --epub-cover-image=cover.jpg \
#     -o ${OUTPUT_BASE_NAME}-${LANGUAGE}.epub $CHAPTERS 

# echo "create docx"
# pandoc --resource-path=.:${FOLDER} \
#     -f markdown \
#     -t docx \
#     --toc -N --columns 10000 --self-contained -s \
#     --reference-doc tools/custom-reference.docx \
#     -o ${OUTPUT_BASE_NAME}-${LANGUAGE}_WIP_.docx $CHAPTERS 

# echo "Create mobi"
# ebook-convert "${OUTPUT_BASE_NAME}-${LANGUAGE}.epub" "${OUTPUT_BASE_NAME}-${LANGUAGE}.mobi"
# # kindlegen ${OUTPUT_BASE_NAME}-${LANGUAGE}.epub

rm tmp_first_page-$LANGUAGE.tex
rm tmp_cover-$LANGUAGE.tex
rm tmp_latex-header-$LANGUAGE.tex
