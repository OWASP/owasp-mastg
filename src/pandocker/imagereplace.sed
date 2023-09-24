s/<img\s*src="\(.*\)"\s*title="\(.*\)"\s*width="\(.*\)"\s*height="\(.*\)"\/>/\![\2](\1){width=\3 height=\4}/g
s/<img\s*src="\(.*\)"\s*alt="\(.*\)"\s*width="\(.*\)"\s*height="\(.*\)"\/>/\![\2](\1){width=\3 height=\4}/g
s/<img\s*src="\(.*\)"\s*title="\(.*\)"\s*width="\(.*\)"\/>/\![\2](\1){width=\3}/g
s/<img\s*src="\(.*\)"\s*alt="\(.*\)"\s*width="\(.*\)"\/>/\![\2](\1){width=\3}/g
s/<img\s*src="\(.*\)"\s*width="\(.*\)"\s*\/>/\![](\1){width=\2}/g
s/<img\s*src="\(.*\)"\s*title="\(.*\)"\/>/\![\2](\1)/g
s/<img\s*src="\(.*\)"\s*alt="\(.*\)"\/>/\![\2](\1)/g
s/<img\s*src="\(.*\)"\/>/\![](\1)/g