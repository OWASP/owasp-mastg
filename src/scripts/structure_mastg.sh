#!/bin/bash

# mkdir -p docs/MASWE

# directories=("tests" "techniques" "tools" "apps" "tests-beta" "demos" "rules")

# for dir in "${directories[@]}"; do
#     cp -r "$dir" docs/MASTG/ || { echo "Failed to copy $dir"; exit 1; }
# done

# cp -r weaknesses/** docs/MASWE/ || { echo "Failed to copy weaknesses"; exit 1; }



if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
else
    SED="sed"
fi

# cp -r Document/Images/ docs/assets/Images/
find docs/MASTG/tests -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/techniques -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/tools -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG/apps -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../../../assets/Images/#g' {} \;
find docs/MASTG -name "*.md" -exec $SED -i 's#<img src="Images/#<img src="../../../assets/Images/#g' {} \;

