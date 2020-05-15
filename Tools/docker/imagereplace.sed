s/<img src="\(.*\)" title="\(.*\)" width="\(.*\)" height="\(.*\)"\s*\/>/\![\2](\1){ width=\3 height=\4}/g
s/<img src="\(.*\)" alt="\(.*\)" width="\(.*\)" height="\(.*\)"\s*\/>/\![\2](\1){ width=\3 height=\4}/g
s/<img src="\(.*\)" title="\(.*\)" width="\(.*\)"\s*\/>/\![\2](\1){ width=\3}/g
s/<img src="\(.*\)" alt="\(.*\)" width="\(.*\)"\s*\/>/\![\2](\1){ width=\3}/g
s/<img src="\(.*\)" title="\(.*\)"\s*\/>/\![\2](\1)/g
s/<img src="\(.*\)" alt="\(.*\)"\s*\/>/\![\2](\1)/g
s/<img src="\(.*\)"\s*\/>/\![\1](\1)/g
s/<img src="\(.*\)" width="\(.*\)"\s*\/>/\![\1](\1){ width=\2}/g