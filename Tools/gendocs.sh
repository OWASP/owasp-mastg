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
    if [ "$LINTRESULT" -eq "0" ]; then
        COMMENT_LINT=""
    elif [ -z "$LINTRESULT"]; then
        COMMENT_LINT=""
    else 
        COMMENT_LINT="Please run the Apply_Linter_check.sh in the tools folder to see where the Lint issues are."
    fi
    if [ "$LINKRESULT" -eq "0" ]; then
        COMMENT_LINK=""
    elif [ -z "$LINKRESULT" ]; then
        COMMENT_LINK=""
    else
        COMMENT_LINK="Please run the Apply_Link_Check.sh in the tools folder to see wherhe the Link issues are."
    fi
    echo "Sending feedback to Github"
    curl -H "Authorization: token ${GITHUB_TOKEN}" -X POST \
    -d "{\"body\": \"Results for commit $TRAVIS_COMMIT: Broken link result: $LINKRESULT .\n $COMMENT_LINK \n Markdown result errorlength: $LINTRESULT .\n $COMMENT_LINT  \"}" \
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