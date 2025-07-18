from pathlib import Path
from structure_mastg import find_md_files, batch_replace
import shutil
import logging

log = logging.getLogger('mkdocs')

def on_pre_build(config):
    docs_dir = Path("docs")
    maswe_docs_dir = docs_dir / "MASWE"

    maswe_candidates = [Path("../maswe"), Path("./maswe")]
    maswe_dir = next((p for p in maswe_candidates if p.is_dir()), None)

    if not maswe_dir:
        raise Exception("Error: Please clone the maswe to same parent directory as mastg: cd .. && git clone https://github.com/OWASP/maswe.git")

    log.info(f"Using MASWE directory: {maswe_dir}")

    # Clean MASWE dir
    if maswe_docs_dir.exists():
        shutil.rmtree(maswe_docs_dir)

    # Copy over the entire weaknesses directory
    shutil.copytree(maswe_dir / "weaknesses", maswe_docs_dir)

    # MASWE fixes
    batch_replace(find_md_files(maswe_dir), [
        ("Document/", "MASTG/")
    ])