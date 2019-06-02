#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
echo "Applying Linter check"
sh ./Apply_Linter_Check.sh
echo "Counting amount of linter issues:"
LINTRESULT=$(wc -l ../linter-result.out)
echo $LINTRESULT
if [ "$TRAVIS_PULL_REQUEST" != "false" ] ; then
    echo "Applying Link check"
    export LINKRESULT=$(sh ./Apply_Link_Check.sh)
    echo "$LINKRESULT"
    echo "Sending feedback to Github"
    curl -H "Authorization: token ${GITHUB_TOKEN}" -X POST \
    -d "{\"body\": \"Results for commit $TRAVIS_COMMIT: \n Broken link result: $LINKRESULT, \n markdown result errorlength: $LINTRESULT. \n If fields are empty or 0: you should be OK. If fields contain data: please check for markdown and link errors. \"}" \
    "https://api.github.com/repos/${TRAVIS_REPO_SLUG}/issues/${TRAVIS_PULL_REQUEST}/comments"
fi
if [ -z "$TRAVIS_TAG" ]; then 
exit 0; 
fi
echo "Running creaton of pdfs and word documents"
sh ./gitbookepubandpdf.sh $TRAVIS_TAG
sh ./generate_document.sh
echo "Checking epub validity"
sh epubcheck ../Generated/MSTG-EN.epub