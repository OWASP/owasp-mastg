#!/bin/bash
for filename in Document/0x05*.md Document/0x06*.md; do
    docker run --rm -u `id -u`:`id -g` -v `pwd`:/pandoc dalibo/pandocker --section-divs -f markdown -t html $filename -o $(basename $filename .md).html
done

mkdir -p Tools/scripts/generated/html
mv *.html Tools/scripts/generated/html