s/<img src="\(.*\)" title="\(.*\)" width="\(.*\)" height="\(.*\)" \/>/\![\2](\1){ width=\3 height=\4}/g
s/<img src="\(.*\)" alt="\(.*\)" width="\(.*\)" height="\(.*\)" \/>/\![\2](\1){ width=\3 height=\4}/g
s/<img src="\(.*\)" title="\(.*\)" width="\(.*\)" \/>/\![\2](\1){ width=\3}/g
s/<img src="\(.*\)" alt="\(.*\)" width="\(.*\)" \/>/\![\2](\1){ width=\3}/g
s/<img src="\(.*\)" width="\(.*\)" \/>/\![\1](\1){ width=\2}/g
s/<img src="\(.*\)" title="\(.*\)" \/>/\![\2](\1)/g
s/<img src="\(.*\)" alt="\(.*\)" \/>/\![\2](\1)/g
s/<img src="\(.*\)" \/>/\![\1](\1)/g