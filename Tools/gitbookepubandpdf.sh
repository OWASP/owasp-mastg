#!/bin/bash
echo "Usage: ./gitbookepubandpdf VERSIONTAG"
echo "Do not forget to install npm, gitbookcli (https://www.npmjs.com/package/gitbook-cli), calibre (brew cask install calibre on Mac OS X)"
echo 'Versiontag is' $1
cp book.json ../book.json
cp ../CHANGELOG.MD ../Document/Changelog.md
sed -i.bak "s/\.\.\/Changelog\.md/Changelog\.md/g" ../Document/SUMMARY.md
sed -i.bak "s/\[\]/$1/g" ../book.json
rm ../book.json.bak
gitbook install ../

gitbook pdf ../ ../Generated/MSTG-EN.pdf
gitbook epub ../ ../Generated/MSTG-EN.epub
gitbook mobi ../ ../Generated/MSTG-EN.mobi
sed  "s/Changelog\.md/\.\.\/Changelog\.md/g" ../Document/SUMMARY.md
rm ../Document/Changelog.md
echo "We are done: please do not forget to update the leanpub update!"
