from pathlib import Path

import shutil
import logging
import os
import re

log = logging.getLogger('mkdocs')

def on_pre_build(config):

    docs_dir = Path("docs")

    structure_mastg(docs_dir)
    maswe_repo = structure_maswe(docs_dir)
    masvs_repo = structure_masvs(docs_dir)

    # Save the values so they can dynamically be watched for changes later
    config['extra']['maswe_repo'] = maswe_repo
    config['extra']['masvs_repo'] = masvs_repo

def structure_maswe(docs_dir):
    # Copy MASWE into docs folder
    maswe_repo_dir = locate_external_repo("maswe")
    maswe_local_dir = docs_dir / "MASWE"
    clean_and_copy(maswe_repo_dir / "weaknesses", maswe_local_dir)

    # MASWE fixes
    batch_replace(find_md_files(maswe_local_dir), [
        ("Document/", "MASTG/")
    ])

    return maswe_repo_dir

def structure_masvs(docs_dir):
    # Copy MASVS into docs folder
    masvs_repo_dir = locate_external_repo("masvs")
    masvs_local_dir = docs_dir / "MASVS"
    clean_and_copy(masvs_repo_dir / "Document", masvs_local_dir)

    # Move the MASVS/controls folder into the docs/MASVS/controls folder
    clean_and_copy(masvs_repo_dir / "controls", masvs_local_dir / "controls")

    # Move the images to the correct location
    masvs_images_dir = docs_dir / "assets" / "MASVS" / "Images"
    masvs_images_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(masvs_local_dir / "images", masvs_images_dir, dirs_exist_ok=True)

    # Replacement patterns
    for md_path in Path(masvs_local_dir).rglob("*.md"):
        if "controls" in str(md_path):
            replace_in_file(md_path, "images/", "../../../assets/MASVS/Images/")
        else:
            replace_in_file(md_path, "images/", "../../assets/MASVS/Images/")

    # The controls pages are prettyfied with some styling
    MAS_BLUE = "499FFF"
    for md_path in Path(masvs_local_dir).rglob("controls/*.md"):
        control_id = md_path.stem
        control_regex = r"## Control\n\n([^#]*)\n\n"
        description_regex = r"## Description\n\n(.*)"

        content = md_path.read_text(encoding="utf-8")
        # Extract the control content
        control_content = re.search(control_regex, content).group(1).strip()
        description_content = re.search(description_regex, content).group(1).strip()

        content = f'# {control_id}\n\n'
        content += f'<p style="font-size: 2em">{control_content}</p>\n\n'
        # add html thick separation line in blue
        content += f'<hr style="height: 0.2em; background-color: #{MAS_BLUE}; border: 0;" />\n\n'
        content += f'{description_content}\n'

        md_path.write_text(content, encoding="utf-8")

    return masvs_repo_dir

def structure_mastg(docs_dir):
    # Move all MASTG folders into the docs folder
    mastg_dir = docs_dir / "MASTG"
    images_dir = docs_dir / "assets" / "Images"

    mastg_dir.mkdir(parents=True, exist_ok=True)
    images_dir.mkdir(parents=True, exist_ok=True)

    directories = ["knowledge", "tests", "techniques", "tools", "apps", "demos", "rules", "utils", "best-practices"]

    for d in directories:
        dest = mastg_dir / d
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(d, dest)

    # Copy beta tests
    for file in Path("tests-beta").rglob("*"):
        if file.is_file():
            rel_path = file.relative_to("tests-beta")
            dest_path = mastg_dir / "tests" / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(file, dest_path)

    # Copy top-level .md files
    for mdfile in Path("Document").glob("0x0*.md"):
        shutil.copy(mdfile, mastg_dir / mdfile.name)

    shutil.copy("Document/index.md", mastg_dir / "index.md")

    # Copy the images directory in its entirety
    shutil.copytree("Document/Images", images_dir, dirs_exist_ok=True)

    # Specific subdir replacements
    rel_paths = {
        "knowledge": "../../../../../assets/Images/",
        "tests": "../../../../../assets/Images/",
        "techniques": "../../../../../assets/Images/",
        "tools": "../../../../../assets/Images/",
        "apps": "../../../../../assets/Images/",
    }

    for subdir, rel_img in rel_paths.items():
        files = find_md_files(mastg_dir / subdir)
        batch_replace(files, [("src=\"Images/", f"src=\"{rel_img}")])

    # Generic MASTG markdown fix
    batch_replace(find_md_files(mastg_dir), [
        ("src=\"Images/", "src=\"../../../assets/Images/"),
        ("Document/", "")
    ])



def locate_external_repo(repo_name):

    repo_candidates = [Path("..") / repo_name, Path(".") / repo_name]
    repo_location = next((p for p in repo_candidates if p.is_dir()), None)

    if not repo_location:
        raise Exception(f"Error: Please clone {repo_name} to the same parent directory as mastg: cd .. && git clone https://github.com/OWASP/{repo_name}.git")

    log.info(f"Using {repo_name.upper()} directory: {repo_location}")

    return repo_location


def clean_and_copy(source, destination):
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, dirs_exist_ok=True)

def clean_and_move(source, destination):
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(source, destination)


def find_md_files(base_dir):
    # Get all md files but strip out md files in node_modules or anything inside hidden directories
    return [p for p in Path(base_dir).rglob("*.md") if not "/node_modules/" in str(p) and not "/." in str(p)]

def batch_replace(filepaths, replacements):
    for file in filepaths:
        for old, new in replacements:
            replace_in_file(file, old, new)


def replace_in_file(file_path, old, new):
    path = Path(file_path)
    content = path.read_text(encoding="utf-8").replace(old, new)
    path.write_text(content, encoding="utf-8")