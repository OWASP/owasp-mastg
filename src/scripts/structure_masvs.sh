if [ -d "../owasp-masvs/" ] ; then
    MASVS_DIR=../owasp-masvs
elif [ ! -d "../owasp-masvs/" ] ; then
    MASVS_DIR=./owasp-masvs
else
    echo "Error: Please clone owasp-masvs to same directory as owasp-mastg"
    exit
fi

mkdir -p docs/MASVS/Intro
mkdir -p docs/MASVS/controls
cp $MASVS_DIR/Document/*.md docs/MASVS
mv docs/MASVS/0[1-4]*.md docs/MASVS/Intro
cp $MASVS_DIR/controls/* docs/MASVS/controls

if [[ "$(uname)" == "Darwin" ]]; then
    SED="gsed"
else
    SED="sed"
fi


mkdir -p docs/assets/Images/MASVS
cp $MASVS_DIR/Document/images/* docs/assets/Images/MASVS
$SED -i "s#images/#../../../assets/Images/MASVS/#g" docs/MASVS/**/*.md
$SED -i "s#images/#../../assets/Images/MASVS/#g" docs/MASVS/*.md