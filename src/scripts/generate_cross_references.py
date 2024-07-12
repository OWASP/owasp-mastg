import yaml
import os
import glob

def gather_metadata(directory, id_field):
    metadata = {}
    for file in glob.glob(f"{directory}/**/*.md", recursive=True):
        with open(file, 'r') as f:
            content = f.read()
            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
            metadata[frontmatter[id_field]] = frontmatter
    return metadata

def generate_cross_references(weaknesses, tests, demos):
    cross_references = {}

    for weakness_id, weakness in weaknesses.items():
        cross_references[weakness_id] = {
            "tests": [],
            "demos": []
        }
        for test_id, test in tests.items():
            if test.get("weakness") == weakness_id:
                cross_references[weakness_id]["tests"].append(test_id)
        for demo_id, demo in demos.items():
            if demo.get("test") in cross_references[weakness_id]["tests"]:
                cross_references[weakness_id]["demos"].append(demo_id)

    return cross_references

def save_yaml(data, filename):
    with open(filename, 'w') as f:
        yaml.dump(data, f)

def main():
    weaknesses = gather_metadata("weaknesses", "id")
    tests = gather_metadata("tests-beta", "id")
    demos = gather_metadata("demos", "id")

    cross_references = generate_cross_references(weaknesses, tests, demos)
    save_yaml(cross_references, "cross_references.yaml")

if __name__ == "__main__":
    main()
