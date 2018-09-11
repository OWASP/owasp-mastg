FILE=$1
RETPATH=`pwd`
rm -rf /var/tmp/docx
mkdir /var/tmp/docx
cp $FILE /var/tmp/docx
cd /var/tmp/docx
mkdir tmp
unzip $FILE -d tmp
cd tmp/word
sed -i "s/${2}/${3}/" document.xml
cd ..
zip -r ../${FILE} *
cp /var/tmp/docx/${FILE} ${RETPATH}
cd $RETPATH
rm -rf /var/tmp/docx 
