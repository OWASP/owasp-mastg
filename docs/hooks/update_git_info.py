import logging
import mkdocs.plugins
import subprocess
import os

log = logging.getLogger('mkdocs')


def get_last_commit_date(file_path):
    if any(keyword in file_path for keyword in ["MASTG-TEST-", "MASTG-TOOL-", "MASTG-TECH-", "MASTG-APP-", "MASTG-DEMO-", "MASTG-BEST-"]):
        if os.getenv("IGNORE_LAST_COMMIT_DATE") == "1":
            return None
        try:
            file_path = file_path.replace("/docs/MASTG/", "/")
            if "MASTG-TEST-02" in file_path:
                file_path = file_path.replace("/tests", "/tests-beta")
            # get the last commit date as "September 12, 2022"
            command = f"git log -n 1 --date=format:'%B %d, %Y' --format=%ad -- {file_path}"
            result = subprocess.check_output(command, shell=True, universal_newlines=True)

            return result.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error executing Git command: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    return None

if __name__ == '__main__':
    print(get_last_commit_date('./CONTRIBUTING.md'))


# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-49)
def on_page_markdown(markdown, page, **kwargs):

    abs_path = page.file.abs_src_path

    if any(substring in abs_path for substring in ["MASWE/", "MASTG/"]) and "index.md" not in abs_path:
        last_updated = get_last_commit_date(abs_path)
        page.meta["last_updated"] = last_updated

    return markdown
