#!/bin/bash
echo "Do not forget to install npm, gitbookcli (https://www.npmjs.com/package/gitbook-cli), calibre (brew cask install calibre)"
gitbook install ../
gitbook pdf ../ ../Generated/MSTG-eng.pdf
gitbook epub ../ ../Generated/MSTG-eng.epub
gitbook mobi ../ ../Generated/MSTG-eng.mobi
