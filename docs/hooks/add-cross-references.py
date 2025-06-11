import logging
import yaml
import mkdocs.plugins
import os
import glob

log = logging.getLogger('mkdocs')


def gather_metadata(directory, id_key):
    metadata = {}
    for file in glob.glob(f"./docs/{directory}/**/*.md", recursive=True):
        if file.endswith("index.md"):
            continue

        with open(file, 'r') as f:
            content = f.read()
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))

            if not id_key in frontmatter:
                if "MASTG-TEST-02" in file:
                    log.error(f"Missing frontmatter ID in {file}")
                continue

            frontmatter["path"] = file.replace("./docs/", "") # os.path.relpath(file, "./docs")

            metadata[frontmatter[id_key]] = frontmatter
    return metadata

def generate_cross_references():
    tests = gather_metadata("MASTG/tests", "id")
    demos = gather_metadata("MASTG/demos", "id")

    cross_references = {
        "weaknesses": {},
        "tests": {},
        "best-practices": {}
    }

    for test_id, test_meta in tests.items():
        weakness_id = test_meta.get("weakness")
        test_path = test_meta.get("path")
        test_title = test_meta.get("title")
        test_platform = test_meta.get("platform")
        best_practices_ids = test_meta.get("best-practices")

        # Create cross-references for weaknesses listing all tests that reference each weakness ID
        if weakness_id:
            if weakness_id not in cross_references["weaknesses"]:
                cross_references["weaknesses"][weakness_id] = []
            cross_references["weaknesses"][weakness_id].append({"id": test_id, "path": test_path, "title": test_title, "platform": test_platform})

        # Create cross-references for best_practices listing all tests that reference each best_practice ID
        if best_practices_ids:
            for best_practice_id in best_practices_ids:
                if best_practice_id not in cross_references["best-practices"]:
                    cross_references["best-practices"][best_practice_id] = []
                cross_references["best-practices"][best_practice_id].append({"id": test_id, "path": test_path, "title": test_title, "platform": test_platform})

    for demo_id, demo_meta in demos.items():
        test_id = demo_meta.get("test")
        demo_path = demo_meta.get("path")
        demo_title = demo_meta.get("title")
        demo_platform = demo_meta.get("platform")

        # Create cross-references for tests listing all demos that reference each test ID
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

@mkdocs.plugins.event_priority(-40)
def on_page_markdown(markdown, page, config, **kwargs):
    path = page.file.src_uri
    meta = page.meta

    cross_references = config.cross_references

    if "MASWE-" in path:
        weakness_id = meta.get('id')

        # Add Tests section to weaknesses as buttons
        # ORIGIN: Cross-references from this script

        if weakness_id in cross_references["weaknesses"]:
            tests = cross_references["weaknesses"][weakness_id]
            meta['tests'] = tests
            if tests:
                tests_section =  "## Tests\n\n"
                for test in tests:
                    relPath = os.path.relpath(test['path'], os.path.dirname(path))
                    tests_section += f"[{get_platform_icon(test['platform'])} {test['id']}: {test['title']}]({relPath}){{: .mas-test-button}} "
                markdown += f"\n\n{tests_section}"

    if "MASTG-TEST-" in path:

        # Add best_practices section to tests as a bullet point list with IDs, links are resolved in a separate hook
        # ORIGIN: Test metadata

        best_practices = meta.get('best-practices')
        if best_practices:
            best_practices_section = "## Mitigations\n\n"
            for best_practice_id in best_practices:
                best_practice_path = f"MASTG/best-practices/{best_practice_id}.md"
                relPath = os.path.relpath(best_practice_path, os.path.dirname(path))
                best_practices_section += f"- @{best_practice_id}\n"

            markdown += f"\n\n{best_practices_section}"

        test_id = meta.get('id')

        # Add Demos section to tests as buttons
        # ORIGIN: Cross-references from this script

        if test_id in cross_references["tests"]:
            demos = cross_references["tests"][test_id]
            meta['demos'] = demos
            if demos:
                demos_section = "## Demos\n\n"
                for demo in demos:
                    relPath = os.path.relpath(demo['path'], os.path.dirname(path))
                    demos_section += f"[{get_platform_icon(demo['platform'])} {demo['id']}: {demo['title']}]({relPath}){{: .mas-demo-button}} "

                markdown += f"\n\n{demos_section}"

    if "MASTG-BEST" in path:
        best_practice_id = meta.get('id')

        # Add Tests section to best_practices as buttons
        # ORIGIN: Cross-references from this script

        if best_practice_id in cross_references["best-practices"]:
            best_practices = cross_references["best-practices"].get(best_practice_id)
            meta['best-practices'] = best_practices
            if best_practices:
                best_practices_section = "## Tests\n\n"
                for best_practice in best_practices:
                    relPath = os.path.relpath(best_practice['path'], os.path.dirname(path))
                    best_practices_section += f"[{get_platform_icon(best_practice['platform'])} {best_practice['id']}: {best_practice['title']}]({relPath}){{: .mas-test-button}} "

                markdown += f"\n\n{best_practices_section}"

    return markdown