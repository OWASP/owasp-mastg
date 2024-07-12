import logging
import yaml
import mkdocs.plugins

log = logging.getLogger('mkdocs')

def load_cross_references():
    with open("cross_references.yaml", 'r') as f:
        return yaml.load(f, Loader=yaml.FullLoader)

def get_platform_icon(platform):
    if platform == "ios":
        return ":material-apple:"
    if platform == "android":
        return ":material-android:"
    return ":material-asterisk:"

cross_references = load_cross_references()

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, **kwargs):
    path = page.file.src_uri
    meta = page.meta

    if "MASWE-" in path:
        weakness_id = meta.get('id')
        if weakness_id in cross_references["weaknesses"]:
            tests = cross_references["weaknesses"][weakness_id]
            meta['tests'] = tests
            if tests:
                tests_section = "## Tests\n\n" + "\n".join([f"<button class='mas-test-button' onclick='window.location=\"{test['path']}\"'>{get_platform_icon(test['platform'])} {test['id']}: {test['title']}</button>" for test in tests])
                markdown += f"\n\n{tests_section}"

    if "MASTG-TEST-" in path:
        test_id = meta.get('id')
        if test_id in cross_references["tests"]:
            demos = cross_references["tests"][test_id]
            meta['demos'] = demos
            if demos:
                demos_section = "## Demos\n\n" + "\n".join([f"<button class='mas-demo-button' onclick='window.location=\"{demo['path']}\"'>{get_platform_icon(demo['platform'])} {demo['id']}: {demo['title']}</button>" for demo in demos])
                markdown += f"\n\n{demos_section}"

    return markdown