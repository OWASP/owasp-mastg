#!/bin/sh
if [ "$TRAVIS_PULL_REQUEST" != "false" ] ; then
   echo "Testing result"
   echo $RESULT
   curl -H "Authorization: token ${GITHUB_TOKEN}" -X POST \
    -d "{\"body\": \"Hello world $RESULT\"}" \
    "https://api.github.com/repos/${TRAVIS_REPO_SLUG}/issues/${TRAVIS_PULL_REQUEST}/comments"
fi
