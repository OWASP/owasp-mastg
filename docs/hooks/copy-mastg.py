import shutil

from pathlib import Path

# Sed-like replacements
def replace_in_file(file_path, old, new):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace(old, new)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

def find_md_files(base_dir):
    # Get all md files but strip out md files in node_modules or anything inside hidden directories
    return [p for p in Path(base_dir).rglob("*.md") if not "/node_modules/" in str(p) and not "/." in str(p)]

def batch_replace(filepaths, replacements):
    for file in filepaths:
        for old, new in replacements:
            replace_in_file(file, old, new)

def on_pre_build(config):
    docs_dir = Path("docs")
    mastg_dir = docs_dir / "MASTG"
    images_dir = docs_dir / "assets" / "Images"

    mastg_dir.mkdir(parents=True, exist_ok=True)
    images_dir.mkdir(parents=True, exist_ok=True)

    directories = ["tests", "techniques", "tools", "apps", "demos", "rules", "utils", "best-practices"]

    for d in directories:
        dest = mastg_dir / d
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(d, dest, dirs_exist_ok=True)

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

    # Copy image assets
    for file in Path("Document/Images").rglob("*"):
        if file.is_file():
            rel_path = file.relative_to("Document/Images")
            dest_path = images_dir / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(file, dest_path)

    # Specific subdir replacements
    rel_paths = {
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
