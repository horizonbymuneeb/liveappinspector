#!/usr/bin/env python3
"""Fail the build when documentation rots.

Checks every markdown file in the repository for:
  * relative links that point at a missing file,
  * anchors that do not match a heading in the target document,
  * image links that resolve to nothing.

`dist/` is a build artifact and is skipped. External URLs are not fetched
(offline-friendly and no flaky network dependency in CI).

Usage:  python scripts/check-docs.py [--quiet]
Exit:   0 = clean, 1 = broken links found
"""
import os
import re
import sys

SKIP_DIRS = {"target", ".git", "dist", "node_modules"}


def slugify(text):
    text = text.strip().lower()
    text = re.sub(r"`|\*|_", "", text)
    text = re.sub(r"[^a-z0-9 \-]", "", text)
    return text.replace(" ", "-")


def headings(path):
    body = open(path, encoding="utf-8").read()
    return {slugify(h) for h in re.findall(r"^#{1,6}\s+(.*)$", body, re.M)}


def main():
    quiet = "--quiet" in sys.argv
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    problems = []
    resolved = 0
    files = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".md"):
                continue
            files += 1
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            text = open(path, encoding="utf-8").read()
            for match in re.finditer(r"\[([^\]]*)\]\(([^)\s]+)\)", text):
                target = match.group(2)
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                file_part, _, anchor = target.partition("#")
                resolved_path = os.path.normpath(os.path.join(dirpath, file_part))
                if not os.path.exists(resolved_path):
                    problems.append(f"{rel}: [{match.group(1)}]({target}) -> missing target")
                    continue
                resolved += 1
                if anchor and resolved_path.endswith(".md"):
                    if slugify(anchor) not in headings(resolved_path):
                        problems.append(f"{rel}: [{match.group(1)}]({target}) -> missing anchor")

    if problems:
        print(f"check-docs: {len(problems)} problem(s) in {files} files")
        for p in problems:
            print("  " + p)
        return 1
    if not quiet:
        print(f"check-docs: {files} markdown files, {resolved} relative links, 0 problems")
    return 0


if __name__ == "__main__":
    sys.exit(main())
