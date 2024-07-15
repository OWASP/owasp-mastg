import logging
import yaml
import mkdocs.plugins
import os
import glob

log = logging.getLogger('mkdocs')


def gather_metadata(directory, id_key):
    metadata = {}
    for file in glob.glob(f"./docs/{directory}/**/MASWE-*.md", recursive=True):
        if file.endswith("index.md"):
            continue

        with open(file, 'r') as f:
            content = f.read()
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
            # path is file without the .md extension, 'weaknesses/MASVS-STORAGE/MASWE-0004.md' -> weaknesses/MASVS-STORAGE/MASWE-0004
            
            if not id_key in frontmatter:
                log.error(f"Missing frontmatter ID in {file}")
                continue

            frontmatter["path"] = file[:-3]
            # replace weaknesses with MASWE in path
            frontmatter["path"] = frontmatter["path"].replace("weaknesses", "/MASWE")
            if directory == "tests-beta" or directory == "demos":
                frontmatter["path"] = frontmatter["path"].replace("tests-beta", "/MASTG/tests-beta")
                frontmatter["path"] = frontmatter["path"].replace("demos", "/MASTG/demos") 

            metadata[frontmatter[id_key]] = frontmatter
    return metadata

def generate_cross_references():
    weaknesses = gather_metadata("MASWE", "id")
    tests = gather_metadata("tests-beta", "id")
    demos = gather_metadata("demos", "id")

    cross_references = {
        "weaknesses": {},
        "tests": {}
    }

    for test_id, test_meta in tests.items():
        weakness_id = test_meta.get("weakness")
        test_path = test_meta.get("path")
        test_title = test_meta.get("title")
        test_platform = test_meta.get("platform")
        if weakness_id:
            if weakness_id not in cross_references["weaknesses"]:
                cross_references["weaknesses"][weakness_id] = []
            cross_references["weaknesses"][weakness_id].append({"id": test_id, "path": test_path, "title": test_title, "platform": test_platform})

    for demo_id, demo_meta in demos.items():
        test_id = demo_meta.get("test")
        demo_path = demo_meta.get("path")
        demo_title = demo_meta.get("title")
        demo_platform = demo_meta.get("platform")
        if test_id:
            if test_id not in cross_references["tests"]:
                cross_references["tests"][test_id] = []
            cross_references["tests"][test_id].append({"id": demo_id, "path": demo_path, "title": demo_title, "platform": demo_platform})


    with open("cross_references.yaml", 'w') as f:
        yaml.dump(cross_references, f)
        
    return cross_references

def get_platform_icon(platform):
    if platform == "ios":
        return ":material-apple:"
    if platform == "android":
        return ":material-android:"
    return ":material-asterisk:"

def on_pre_build(config):
    config.cross_references = generate_cross_references()

@mkdocs.plugins.event_priority(-50)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri
    meta = page.meta

    cross_references = config.cross_references

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