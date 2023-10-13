# semgrep -c ./rule.yaml ./snippet.java --json | python3 -m json.tool > output.json

NO_COLOR=true semgrep -c ./rule.yaml ./snippet.java --text -q > output.txt