import os
import shutil
import platform
from pathlib import Path
import glob
import logging
import checklist_utils

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

    # maswe_docs_dir.mkdir(parents=True, exist_ok=True)

    # Copy over the entire weaknesses directory
    shutil.copytree(maswe_dir / "weaknesses", maswe_docs_dir)

