
import re
import mkdocs.plugins

def extract_github_repo(url):
    match = re.search(r'github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$', url)
    if match:
        return match.group(1), match.group(2)
    return None


# https://www.mkdocs.org/dev-guide/plugins/#on_page_markdown
@mkdocs.plugins.event_priority(-40)
def on_page_markdown(markdown, page, **kwargs):

    if source := page.meta.get("source"):
        info = extract_github_repo(source)
        if info:
            account, repo = info
            return f"""
[![](https://github-readme-stats.vercel.app/api/pin/?username={account}&repo={repo}&show_owner=true&theme=calm){{.floating-right .dark-img}}]({source}){{:target="_blank"}}
[![](https://github-readme-stats.vercel.app/api/pin/?username={account}&repo={repo}&show_owner=true){{.floating-right .light-img}}]({source}){{:target="_blank"}}
""" + markdown

    return markdown
