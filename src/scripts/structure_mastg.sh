#!/bin/bash

mkdir -p docs/MASWE

directories=("tests" "techniques" "tools" "apps" "tests-beta" "demos" "rules")

for dir in "${directories[@]}"; do
    cp -r "$dir" docs/MASTG/ || { echo "Failed to copy $dir"; exit 1; }
done

cp -r weaknesses/** docs/MASWE/ || { echo "Failed to copy weaknesses"; exit 1; }

cp -r Document/0x0*.md docs/MASTG
cp docs/MASTG/0x08b-Reference-Apps.md docs/MASTG/apps/index.md
cp docs/MASTG/0x08a-Testing-Tools.md docs/MASTG/tools/index.md
cp Document/tests.md docs/MASTG/tests/index.md
cp Document/techniques.md docs/MASTG/techniques/index.md

if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
else
    SED="sed"
fi

cp -r Document/Images/ docs/assets/Images/
find docs/MASTG/tests -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/techniques -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/tools -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/apps -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../assets/Images/#g' {} \;

