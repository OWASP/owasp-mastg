#!/bin/sh
cd $TRAVIS_BUILD_DIR/Tools
echo "Applying Linter check"
sh ./Apply_Linter_Check.sh
echo "Counting amount of linter issues:"
LINTRESULT=$(wc -l ../linter-result.out)
echo $RESULT
if [ "$TRAVIS_PULL_REQUEST" != "false" ] ; then
    echo "Applying Link check"
    LINKRESULT:$(sh ./Apply_Link_Check.sh)
    echo "$LINKRESULT"
    echo "Sending feedback to Github"
    curl -H "Authorization: token ${GITHUB_TOKEN}" -X POST \
    -d "{\"body\": \"Broken link result: $LINKRESULT, markdown result errorlength: $LINTRESULT\"}" \
    "https://api.github.com/repos/${TRAVIS_REPO_SLUG}/issues/${TRAVIS_PULL_REQUEST}/comments"
fi
if [ -z "$TRAVIS_TAG" ]; then 
exit 0; 
fi
echo "Running creaton of pdfs and word documents"
sh ./gitbookepubandpdf.sh $TRAVIS_TAG
sh ./generate_document.sh