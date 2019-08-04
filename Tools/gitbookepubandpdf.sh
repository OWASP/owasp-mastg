#!/bin/bash
# echo "Usage: ./gitbookepubandpdf VERSIONTAG"
# echo "Do not forget to install npm, gitbookcli (https://www.npmjs.com/package/gitbook-cli), calibre (brew cask install calibre on Mac OS X)"
# echo 'Versiontag is' $1
# cp book.json ../book.json
# sed -i.bak "s/\[\]/$1/g" ../book.json
# rm ../book.json.bak
# gitbook install ../

gitbook pdf ../ ../Generated/MSTG-EN.pdf
gitbook mobi ../ ../Generated/MSTG-EN.mobi
gsed -i.bak '/http/b; s/\.md#/.html#/' ../Document/*
rm ../Document/*.bak
gitbook epub ../ ../Generated/MSTG-EN.epub
gsed -i.bak '/http/b; s/\.html#/.md#/' ../Document/*
rm ../Document/*.bak


echo "We are done: please do not forget to update the leanpub update!"
