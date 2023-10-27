# semgrep -c ./rule.yaml ./snippet.xml --json | python3 -m json.tool > output.json

NO_COLOR=true semgrep -c . ./snippet* --text -q > output.txt