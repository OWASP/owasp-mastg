import os
import yaml
import glob

def gather_metadata(directory, id_key):
    metadata = {}
    for file in glob.glob(f"{directory}/**/*.md", recursive=True):
        if file.endswith("index.md"):
            continue
        with open(file, 'r') as f:
            content = f.read()
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
            # path is file without the .md extension, 'weaknesses/MASVS-STORAGE/MASWE-0004.md' -> weaknesses/MASVS-STORAGE/MASWE-0004
            frontmatter["path"] = file[:-3]
            # replace weaknesses with MASWE in path
            frontmatter["path"] = frontmatter["path"].replace("weaknesses", "/MASWE")
            if directory == "tests-beta" or directory == "demos":
                frontmatter["path"] = frontmatter["path"].replace("tests-beta", "/MASTG/tests-beta")
                frontmatter["path"] = frontmatter["path"].replace("demos", "/MASTG/demos") 

            metadata[frontmatter[id_key]] = frontmatter
    return metadata

def generate_cross_references():
    weaknesses = gather_metadata("weaknesses", "id")
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

if __name__ == "__main__":
    generate_cross_references()