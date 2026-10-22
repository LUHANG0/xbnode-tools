#!/usr/bin/env python3
"""Export this directory as a standalone repository, including dotfiles."""
from pathlib import Path
import argparse
import tarfile

base = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("output", type=Path)
args = parser.parse_args()
args.output.parent.mkdir(parents=True, exist_ok=True)
with tarfile.open(args.output, "w:gz") as archive:
    for path in sorted(base.rglob("*")):
        rel = path.relative_to(base)
        if any(part in (".git", ".build", "dist", "__pycache__") for part in rel.parts):
            continue
        if path.is_file() and path.resolve() != args.output.resolve():
            archive.add(path, arcname="xbnode-tools/" + str(rel))
print(args.output.resolve())
