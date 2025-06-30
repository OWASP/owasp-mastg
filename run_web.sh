#!/bin/bash

# By default, don't update the last commit date in the footer since it's really slow
IGNORE_LAST_COMMIT_DATE=1 mkdocs serve -a localhost:8000

# You can use --dirty-reload to save time too, but it can lead to broken links
# IGNORE_LAST_COMMIT_DATE=1 mkdocs serve -a localhost:8000 --dirty-reload

# You can expose the site on your public interface by using 0.0.0.0
# IGNORE_LAST_COMMIT_DATE=1 mkdocs serve -a 0.0.0.0:8000

# You can add your GITHUB_TOKEN just like the IGNORE_LAST_COMMIT_DATE. If you do this, make a copy of this file so that you don't accidentally commit your token.
# GITHUB_TOKEN=your_token IGNORE_LAST_COMMIT_DATE=1 mkdocs serve -a localhost:8000