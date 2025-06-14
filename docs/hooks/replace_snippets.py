import logging
import re
import mkdocs.plugins

log = logging.getLogger('mkdocs')

# https://facelessuser.github.io/pymdown-extensions/extensions/tabbed/
# https://facelessuser.github.io/pymdown-extensions/extensions/snippets/
# https://squidfunk.github.io/mkdocs-material/setup/extensions/python-markdown-extensions/#tabbed
# https://squidfunk.github.io/mkdocs-material/setup/extensions/python-markdown-extensions/#snippets

@mkdocs.plugins.event_priority(-40)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri

    # Only apply the transformation if the page is a demo file
    if "MASTG-DEMO-" in path:
        def replace_placeholder(match):
            files = match.group(1).split('#')
            if len(files) == 1:
                filename = files[0].strip()
                return f'```py linenums="1" title="{filename}"\n--8<-- "{filename}"\n```'
            else:
                tabbed_content = ""
                for file in files:
                    file = file.strip()
                    title = file.split("/")[-1]
                    language = file.split(".")[-1]
                    if language == "kt":
                        language = "kotlin"
                    elif language == "sh":
                        language = "shell"
                    tabbed_content += f'=== "{title}"\n\n'
                    tabbed_content += f'    ```{language} linenums="1"\n'
                    tabbed_content += f'    --8<-- "{file}"\n'
                    tabbed_content += f'    ```\n\n'
                return tabbed_content

        updated_markdown = re.sub(r'\{\{\s*(.*?)\s*\}\}', replace_placeholder, markdown)
        return updated_markdown

    # If the page is not a demo, return the original markdown unchanged
    return markdown
