#!/bin/bash

./src/scripts/structure_maswe.sh

# By default, serve on localhost port 8000
mkdocs serve -a localhost:8000

# You can use --dirty-reload to save time too, but it can lead to broken links
# mkdocs serve -a localhost:8000 --dirty-reload

# You can expose the site on your public interface by using 0.0.0.0
# mkdocs serve -a 0.0.0.0:8000

# You can add your GITHUB_TOKEN as an environment var. If you do this, make a copy of this file so that you don't accidentally commit your token.
# GITHUB_TOKEN=your_token  mkdocs serve -a localhost:8000
