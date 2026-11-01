#!/usr/bin/env python3
"""Redact a LiveAppInspector report so it can be shared publicly.

An acquisition report is full of host-identifying data: account names, SIDs, host
names, user profile paths, local and remote addresses, window titles. This script
rewrites those values to lab placeholders so a report (or the exhibit rendered
from it) can be attached to an issue, a blog post or a repository without leaking
a real case.

Strategy: the script reads the identifiers *out of the report itself* (account
name, domain, host name, machine SID, session user) and then removes those tokens
everywhere they appear - including deep inside handle names, registry keys,
autostart commands, environment blocks and custody-log details. That is the only
reliable way to avoid leaks, because the same string is scattered across dozens
of nested fields.

Usage:
    lai inspect --pid 1234 --json report.json
    python scripts/sanitize-report.py report.json redacted.json
    lai render redacted.json --reseal --html redacted.html

Kept on purpose (useful, not personally identifying): binary hashes, PE facts,
module lists, socket states, timestamps. Review the output before publishing.
"""
import json
import re
import sys

BS = chr(92)                      # a single literal backslash
SEP = re.escape(BS)               # regex fragment matching one backslash
DOC_IP = "203.0.113.10"           # RFC 5737 documentation address

STATIC = [
    # user profile paths, JSON-escaped form first
    (re.compile(r"[A-Za-z]:" + SEP + SEP + r"Users" + SEP + SEP + r"[^" + SEP + r"' ]+"),
     "C:" + BS * 2 + "Users" + BS * 2 + "analyst"),
    (re.compile(r"[A-Za-z]:" + SEP + r"Users" + SEP + r"[^" + SEP + r"' ]+"),
     "C:" + BS + "Users" + BS + "analyst"),
    (re.compile(r"%USERPROFILE%"), "C:" + BS + "Users" + BS + "analyst"),
    # private address space -> documentation range
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), DOC_IP),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), DOC_IP),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), DOC_IP),
]

FIELDS = {
    "case.case_id": "IR-0000-000",
    "case.examiner": "A. Examiner",
    "case.organization": "Example Org",
    "case.notes": "redacted for publication",
    "tool.host.computer_name": "WS-DFIR-01",
    "tool.host.dns_hostname": "ws-dfir-01.example.local",
    "tool.host.dns_domain": "example.local",
    "process.pid": 4242,
    "process.parent_pid": 4000,
    "selection.window.title": "Example Application",
    "selection.screen_x": 640,
    "selection.screen_y": 360,
    "user_context.sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
    "user_context.account_name": "analyst",
    "user_context.account_domain": "LAB",
    "user_context.token.authentication_id": "00000000-00000011",
    "user_context.token.token_id": "00000000-00000012",
    "user_context.token.owner_sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
    "user_context.session.username": "analyst",
    "user_context.session.domain": "LAB",
    "user_context.session.client_name": "",
    "user_context.session.client_address": "",
}


def get_path(doc, path):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def set_path(doc, path, value):
    parts = path.split(".")
    cur = doc
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return
        cur = cur[part]
    if isinstance(cur, dict) and parts[-1] in cur:
        cur[parts[-1]] = value


def identity_patterns(report):
    """Build (regex, replacement) pairs from the identifiers found in the report."""
    pairs = []

    def add(value, replacement, min_len=3):
        if isinstance(value, str) and len(value) >= min_len:
            pairs.append((re.compile(re.escape(value), re.IGNORECASE), replacement))

    add(get_path(report, "user_context.account_name"), "analyst")
    add(get_path(report, "user_context.session.username"), "analyst")
    add(get_path(report, "user_context.account_domain"), "LAB")
    add(get_path(report, "user_context.session.domain"), "LAB")
    add(get_path(report, "tool.host.computer_name"), "WS-DFIR-01")
    add(get_path(report, "tool.host.dns_hostname"), "ws-dfir-01.example.local")
    add(get_path(report, "tool.host.dns_domain"), "example.local")

    # Machine SID: S-1-5-21-A-B-C-<rid> -> keep the shape, lose the identity.
    sid = get_path(report, "user_context.sid") or ""
    if sid.startswith("S-1-5-21-"):
        parts = sid.split("-")
        if len(parts) >= 7:
            add("-".join(parts[:6]) + "-", "S-1-5-21-1111111111-2222222222-3333333333-")

    # Longest first so a domain is not clipped by a shorter substring rule.
    pairs.sort(key=lambda p: -len(p[0].pattern))
    return pairs


def scrub(value, patterns):
    if isinstance(value, dict):
        return {k: scrub(v, patterns) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, patterns) for v in value]
    if isinstance(value, str):
        out = value
        for pattern, replacement in patterns:
            out = pattern.sub(lambda _m, r=replacement: r, out)
        return out
    return value


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)

    with open(sys.argv[1], encoding="utf-8-sig") as fh:
        report = json.load(fh)

    patterns = identity_patterns(report) + STATIC
    report = scrub(report, patterns)

    for path, value in FIELDS.items():
        set_path(report, path, value)

    integrity = report.get("integrity")
    if isinstance(integrity, dict):
        # Redaction invalidates the seal: say so instead of shipping a document
        # that claims an integrity it no longer has.
        integrity["report_sha256"] = ""
        integrity["sealed_at_utc"] = ""
        warnings = integrity.setdefault("warnings", [])
        warnings.append(
            "REDACTED: this report was redacted with scripts/sanitize-report.py and is "
            "not covered by the original seal; re-seal with `lai render --reseal`"
        )

    with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print("wrote " + sys.argv[2])
    print("re-seal and render with:  lai render redacted.json --reseal --html redacted.html")


if __name__ == "__main__":
    main()
