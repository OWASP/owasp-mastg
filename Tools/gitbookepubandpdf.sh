#!/bin/bash
echo "Usage: ./gitbookepubandpdf VERSIONTAG"
echo "Do not forget to install npm, gitbookcli (https://www.npmjs.com/package/gitbook-cli), calibre (brew cask install calibre)"
echo 'Versiontag is' $1
cp book.json ../book.json
sed -i.bak "s/\[\]/$1/g" ../book.json
rm ../book.json.bak
gitbook install ../

gitbook pdf ../ ../Generated/MSTG-eng.pdf
gitbook epub ../ ../Generated/MSTG-eng.epub
gitbook mobi ../ ../Generated/MSTG-eng.mobi

echo "We are done: please do not forget to update the leanpub update!"
