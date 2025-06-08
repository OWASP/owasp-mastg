#!/bin/bash

# Default package name
if [ -z "$1" ]; then
    echo "No package name provided. Usage: $0 <package_name>"
    exit 1

else
    package_name="$1"
fi

adb backup -apk -nosystem $package_name
tail -c +25 backup.ab | python3 -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > backup.tar
tar xvf backup.tar

echo "Done, extracted as apps/ to current directory"