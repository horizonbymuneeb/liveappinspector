#!/usr/bin/env python3
"""Assemble the GitHub Pages source tree from the repository's markdown.

Why generate instead of duplicating
-----------------------------------
The repository keeps one copy of every document (README.md, docs/*.md, the JSON
schema, the screenshots) because a duplicated doc set drifts immediately. This
script lays those files out at the *same relative depth* they already use, so a
relative link keeps working untouched:

    site-src/
      index.md                 <- README.md  (site home)
      ARCHITECTURE.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md
      docs/*.md                <- docs/*.md
      docs/screenshots/*.png   <- so <img src="docs/screenshots/..."> keeps resolving
      schema/report-v1.schema.json
      samples/README.md
      LICENSE

Rewrites performed (and nothing else):
  * references to README.md become the site home page (index.md), because MkDocs
    refuses a README.md that collides with index.md;
  * `mkdocs build --strict` then fails loudly if any link or nav entry breaks.
  * a link to the DEPLOYMENT anchor is left intact - GitHub and MkDocs slug
    headings identically for plain ASCII headings.

Usage:  python scripts/build-docs-site.py [--out site-src]
"""
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(ROOT, "site-src")

ROOT_DOCS = [
    "README.md",
    "ARCHITECTURE.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
]

NL = chr(10)


def copy_md(src, dst):
    """Copy a markdown page, pointing README references at the site home."""
    body = open(src, encoding="utf-8").read()
    for old, new in (
        ("](../README.md", "](../index.md"),
        ("](./README.md", "](index.md"),
        ("](README.md", "](index.md"),
    ):
        body = body.replace(old, new)
    with open(dst, "w", encoding="utf-8", newline=NL) as fh:
        fh.write(body)


def main():
    out = DEFAULT_OUT
    if "--out" in sys.argv:
        out = os.path.join(ROOT, sys.argv[sys.argv.index("--out") + 1])

    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    # 1) README becomes the home page; the other root documents keep their names.
    copy_md(os.path.join(ROOT, "README.md"), os.path.join(out, "index.md"))
    for name in ROOT_DOCS:
        if name == "README.md":
            continue
        copy_md(os.path.join(ROOT, name), os.path.join(out, name))

    # 2) docs/ (markdown + screenshots)
    docs_out = os.path.join(out, "docs")
    os.makedirs(docs_out)
    for name in sorted(os.listdir(os.path.join(ROOT, "docs"))):
        src = os.path.join(ROOT, "docs", name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(docs_out, name))
        elif name.endswith(".md"):
            copy_md(src, os.path.join(docs_out, name))

    # 3) machine-readable contract, sample guidance, licence
    shutil.copytree(os.path.join(ROOT, "schema"), os.path.join(out, "schema"))
    os.makedirs(os.path.join(out, "samples"))
    shutil.copy2(os.path.join(ROOT, "samples", "README.md"), os.path.join(out, "samples"))
    shutil.copy2(os.path.join(ROOT, "LICENSE"), os.path.join(out, "LICENSE"))

    # 4) GitHub Pages: skip Jekyll processing
    open(os.path.join(out, ".nojekyll"), "w").close()

    pages = sum(1 for _, _, files in os.walk(out) for f in files if f.endswith(".md"))
    print(f"build-docs-site: {pages} markdown pages staged in {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
