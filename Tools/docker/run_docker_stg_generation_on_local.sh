#!/bin/bash

# NOTE: You can run this script on your local machine e.g. macOS where Docker is installed.

set -euo pipefail

if [ -z ${1+x} ]
then
      VERSION="SNAPSHOT"
else
      VERSION=$1
fi

echo "Version = ${VERSION}"

# export IMG="owasp/mstg-docgenerator:0.2"
# docker pull $IMG
# only use this when you are updating the docker tooling
export IMG="owasp/mstg-docgenerator:latest"
if [[ "$(docker images -q $IMG 2> /dev/null)" == "" ]]; then
  docker build --tag $IMG tools/docker/
fi

export folder=Document
echo "Generating $folder"
[ -f $folder-temp ] && rm -rf $folder-temp
cp -r $folder $folder-temp
docker run --rm -u `id -u`:`id -g` -v ${PWD}:/pandoc $IMG "/pandoc_makedocs.sh $folder-temp ${VERSION}" || echo "$folder failed" &



wait

# echo "Cleaning up"
# for folder in Document*; do
#     if [ -d "$folder-temp" ]; then 
#         rm -Rf $folder-temp
#     fi
# done

# rm tmp-*
