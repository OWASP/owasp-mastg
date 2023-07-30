import glob
import yaml


def get_platform(input_file: str) -> str:
    if "/android/" in input_file:
        return "android"
    elif "/ios/" in input_file:
        return "ios"

def get_mastg_tests_dict():

    mastg_tests = {}

    for file in glob.glob("tests/**/*.md", recursive=True):
        with open(file, 'r') as f:
            id = ""
            content = f.read()
            platform = get_platform(file)

            frontmatter = next(yaml.load_all(content, Loader=yaml.FullLoader))
            masvs_v2_id = frontmatter['masvs_v2_id']
            frontmatter['path'] = file
            if masvs_v2_id:
                id = masvs_v2_id[0] 
                if id not in mastg_tests:
                    mastg_tests[id] = {}
                if platform not in mastg_tests[id]:
                    mastg_tests[id][platform] = []
                mastg_tests[id][platform].append(frontmatter)
            else:
                print(f"No MASVS v2 coverage for: {frontmatter['title']} (was {frontmatter['masvs_v1_id']})")
    return mastg_tests

# with open('mastg_tests.yaml', 'w') as f:
#     f.write(yaml.dump(get_mastg_tests_dict(), indent=4, sort_keys=False))
