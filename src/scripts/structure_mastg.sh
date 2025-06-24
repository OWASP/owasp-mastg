#!/bin/bash
set -euo pipefail

mkdir -p docs/MASTG
mkdir -p docs/MASWE
mkdir -p docs/assets/Images

directories=("tests" "techniques" "tools" "apps" "demos" "rules" "utils" "best-practices")

for dir in "${directories[@]}"; do
    rm -rf "docs/MASTG/$dir"
    cp -r "$dir" docs/MASTG/ || { echo "Failed to copy $dir"; exit 1; }
done

cp -r tests-beta/** docs/MASTG/tests/ || { echo "Failed to copy tests"; exit 1; }

cp -r weaknesses/** docs/MASWE/ || { echo "Failed to copy weaknesses"; exit 1; }

cp -r Document/0x0*.md docs/MASTG
cp -r Document/index.md docs/MASTG

cp -r Document/Images/* docs/assets/Images/

if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
else
    SED="sed"
fi

find docs/MASTG/tests -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/techniques -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/tools -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/apps -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../assets/Images/#g' {} \;

find docs/MASTG -name "*.md" -exec $SED -i 's#Document/##g' {} \;
find docs/MASWE -name "*.md" -exec $SED -i 's#Document/#MASTG/#g' {} \;
