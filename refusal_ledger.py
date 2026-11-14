#!/usr/bin/env python3
"""refusal_ledger: an append-only JSONL ledger of refusals.

Every refusal is recorded the moment it happens, beside the id and the
version of the rule that issued it, and whether the rule lookup even
succeeded. Rows are hash-chained so edits, deletions and reordering are
detectable after the fact.

Standard library only. See README.md for usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

EX_OK = 0
EX_ERROR = 1
EX_USAGE = 2

# Fields that make up a row's content (everything the hash covers).
CONTENT_FIELDS = (
    "seq",
    "ts",
    "input",
    "input_lossy",
    "rule",
    "rule_version",
    "lookup",
    "verdict",
    "note",
)
# All fields a row may carry. Anything else fails verify.
ROW_FIELDS = CONTENT_FIELDS + ("prev", "hash")

LOOKUPS = ("ok", "miss")
DEFAULT_LEDGER = "refusals.jsonl"
ENV_LEDGER = "REFUSAL_LEDGER"

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def now_ts() -> str:
    """Current UTC time, ISO 8601 with microseconds, e.g. 2026-11-14T00:12:33.123456Z."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def ledger_path(args: argparse.Namespace) -> str:
    return args.ledger or os.environ.get(ENV_LEDGER) or DEFAULT_LEDGER


def canonical_bytes(row: dict) -> bytes:
    """The exact bytes a row's hash covers: content fields only, canonical JSON."""
    payload = {k: row[k] for k in CONTENT_FIELDS if k in row}
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def row_hash(row: dict) -> str:
    return hashlib.sha256(canonical_bytes(row)).hexdigest()


def read_ledger(path: str):
    """Return (entries, problems): entries are (lineno, row-or-junk) pairs."""
    entries, problems = [], []
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    entries.append((lineno, json.loads(line)))
                except json.JSONDecodeError as exc:
                    problems.append("line %d: not valid JSON (%s)" % (lineno, exc.msg))
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError) as exc:
        problems.append("cannot read ledger: %s" % (exc,))
    return entries, problems


def append_row(path: str, row: dict) -> None:
    """Append one row as a single fsynced line. The ledger is never rewritten."""
    line = json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n"
    with open(path, "a", encoding="ascii", newline="") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def rule_ref(row: dict) -> str:
    """Display form of a rule: id@version, or id@(unresolved) when lookup missed."""
    ref = str(row.get("rule") or "?")
    version = row.get("rule_version")
    ref += "@" + str(version) if version else "@(unresolved)"
    return ref


def readable(text: str) -> str:
    """Make arbitrary input safe to print: lossy-encode, flatten newlines."""
    safe = text.encode("utf-8", "replace").decode("utf-8")
    return safe.replace("\r", "\\r").replace("\n", "\\n")


# ---------------------------------------------------------------- commands


def cmd_log(args: argparse.Namespace) -> int:
    path = ledger_path(args)

    if args.stdin:
        data = sys.stdin.buffer.read()
        try:
            text = data.decode("utf-8")
            lossy = False
        except UnicodeDecodeError:
            text = data.decode("utf-8", "replace")
            lossy = True
        # Drop one trailing newline; keep everything else exactly as received.
        if text.endswith("\n"):
            text = text[:-1]
        if text.endswith("\r"):
            text = text[:-1]
    else:
        text, lossy = (args.input or ""), False

    if not text:
        print("refusal log: empty input; there is nothing to record", file=sys.stderr)
        return EX_USAGE
    if args.lookup == "ok" and not args.rule_version:
        print(
            "refusal log: --lookup ok requires --version; a no from a live rule must carry"
            " the version that issued it. If the rule could not be looked up, pass --lookup miss.",
            file=sys.stderr,
        )
        return EX_USAGE
    if args.lookup == "miss" and args.rule_version:
        print(
            "refusal log: --version contradicts --lookup miss; a missed lookup cannot know the version.",
            file=sys.stderr,
        )
        return EX_USAGE

    entries, problems = read_ledger(path)
    if problems:
        for p in problems:
            print("refusal log: %s" % p, file=sys.stderr)
        print("refusal log: refusing to append to a ledger I cannot fully read", file=sys.stderr)
        return EX_ERROR

    seq, prev = 1, None
    if entries:
        last = entries[-1][1]
        if isinstance(last, dict):
            s = last.get("seq")
            seq = s + 1 if isinstance(s, int) and not isinstance(s, bool) else len(entries) + 1
            prev = last.get("hash")

    row = {
        "seq": seq,
        "ts": now_ts(),
        "input": text,
        "input_lossy": lossy,
        "rule": args.rule,
        "rule_version": args.rule_version,
        "lookup": args.lookup,
        "verdict": args.verdict,
        "note": args.note,
        "prev": prev,
    }
    row["hash"] = row_hash(row)
    append_row(path, row)
    print("logged #%d %s -> %s" % (row["seq"], rule_ref(row), path))
    return EX_OK


def cmd_show(args: argparse.Namespace) -> int:
    path = ledger_path(args)
    entries, problems = read_ledger(path)
    for p in problems:
        print("warning: %s" % p, file=sys.stderr)
    rows = [row for _, row in entries]
    if args.tail is not None:
        rows = rows[-args.tail :] if args.tail > 0 else []

    if args.json:
        for row in rows:
            print(json.dumps(row, ensure_ascii=True, sort_keys=True))
        return EX_OK

    for row in rows:
        if not isinstance(row, dict):
            print("unparseable row: %r" % (row,))
            continue
        print(
            "#%s %s lookup=%s rule=%s verdict=%s"
            % (
                row.get("seq"),
                row.get("ts"),
                row.get("lookup"),
                rule_ref(row),
                row.get("verdict"),
            )
        )
        print("   input: %s" % readable(str(row.get("input", ""))))
        if row.get("input_lossy"):
            print("   (input was not valid utf-8; stored lossily)")
        if row.get("note"):
            print("   note: %s" % row["note"])
    return EX_OK


def cmd_count(args: argparse.Namespace) -> int:
    path = ledger_path(args)
    entries, problems = read_ledger(path)
    for p in problems:
        print("warning: %s" % p, file=sys.stderr)
    rows = [row for _, row in entries if isinstance(row, dict)]
    if args.rule:
        rows = [r for r in rows if r.get("rule") == args.rule]
    if args.lookup:
        rows = [r for r in rows if r.get("lookup") == args.lookup]

    by_rule: dict = {}
    by_lookup = {"ok": 0, "miss": 0}
    for r in rows:
        ref = rule_ref(r)
        by_rule[ref] = by_rule.get(ref, 0) + 1
        lookup = r.get("lookup")
        if lookup in by_lookup:
            by_lookup[lookup] += 1
    summary = {"total": len(rows), "by_rule": by_rule, "by_lookup": by_lookup}
    print(json.dumps(summary, indent=2, sort_keys=True))
    return EX_OK


def check_row(row, expected_seq: int, expected_prev):
    """Return a list of problems with one row against the schema and the chain."""
    errs = []
    if not isinstance(row, dict):
        return ["row is not a JSON object"]
    unknown = sorted(set(row) - set(ROW_FIELDS))
    if unknown:
        errs.append("unknown field(s): " + ", ".join(unknown))
    missing = sorted({"ts", "input", "input_lossy", "rule", "rule_version", "lookup", "verdict", "seq", "hash"} - set(row))
    if missing:
        errs.append("missing field(s): " + ", ".join(missing))

    ts = row.get("ts")
    if not isinstance(ts, str) or not ts:
        errs.append("ts must be a non-empty string")
    if not isinstance(row.get("input"), str):
        errs.append("input must be a string")
    if not isinstance(row.get("input_lossy"), bool):
        errs.append("input_lossy must be a boolean")
    rule = row.get("rule")
    if not isinstance(rule, str) or not rule:
        errs.append("rule must be a non-empty string")

    lookup = row.get("lookup")
    if lookup not in LOOKUPS:
        errs.append("lookup must be 'ok' or 'miss'")
    version = row.get("rule_version")
    if version is not None and not (isinstance(version, str) and version):
        errs.append("rule_version must be a non-empty string or null")
    if lookup == "ok" and version is None:
        errs.append("lookup ok but rule_version is null: a live rule must carry its version")
    if lookup == "miss" and version is not None:
        errs.append("lookup miss but rule_version is set: a missed lookup cannot know the version")

    verdict = row.get("verdict")
    if not isinstance(verdict, str) or not verdict:
        errs.append("verdict must be a non-empty string")
    note = row.get("note")
    if note is not None and not isinstance(note, str):
        errs.append("note must be a string or null")

    seq = row.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        errs.append("seq must be an integer")
    elif seq != expected_seq:
        errs.append("expected seq %d, found %r" % (expected_seq, seq))

    prev = row.get("prev")
    if prev is not None and not (isinstance(prev, str) and HEX64.match(prev)):
        errs.append("prev must be null or a 64-char sha256 hex string")
    elif prev != expected_prev:
        errs.append("prev does not match the previous row's hash")

    h = row.get("hash")
    if not (isinstance(h, str) and HEX64.match(h)):
        errs.append("hash must be a 64-char sha256 hex string")
    else:
        try:
            if row_hash(row) != h:
                errs.append("stored hash does not match row content")
        except (TypeError, ValueError):
            errs.append("row content cannot be hashed")
    return errs


def cmd_verify(args: argparse.Namespace) -> int:
    path = ledger_path(args)
    entries, problems = read_ledger(path)
    expected_seq, expected_prev, bad_rows = 1, None, 0
    for lineno, row in entries:
        errs = check_row(row, expected_seq, expected_prev)
        for e in errs:
            problems.append("line %d: %s" % (lineno, e))
        if errs:
            bad_rows += 1
        if isinstance(row, dict):
            h, s = row.get("hash"), row.get("seq")
            if isinstance(h, str) and HEX64.match(h):
                expected_prev = h
            if isinstance(s, int) and not isinstance(s, bool):
                expected_seq = s + 1
            else:
                expected_seq += 1
    for p in problems:
        print(p)
    if problems:
        print("FAILED: %d problem(s) across %d row(s) in %s" % (len(problems), bad_rows, path))
        return EX_ERROR
    print("ok: %d row(s) verified, hash chain intact (%s)" % (len(entries), path))
    return EX_OK


# ------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="refusal",
        description="Append-only ledger of refusals, each stored beside the id and version of the rule that issued it.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, help_text, fn):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument(
            "--ledger",
            metavar="PATH",
            default=None,
            help="ledger file (default: $REFUSAL_LEDGER or ./refusals.jsonl)",
        )
        sp.set_defaults(fn=fn)
        return sp

    lp = add("log", "record one refusal, the moment it happens", cmd_log)
    lp.add_argument("input", nargs="?", default=None, help="the input exactly as received (prefix with -- if it starts with '-')")
    lp.add_argument("--stdin", action="store_true", help="read the input verbatim from stdin instead of argv")
    lp.add_argument("--rule", required=True, help="id of the rule that issued the refusal")
    lp.add_argument("--version", dest="rule_version", default=None, help="version of that rule (required unless --lookup miss)")
    lp.add_argument("--lookup", choices=LOOKUPS, default="ok", help="did the rule lookup succeed? (default: ok)")
    lp.add_argument("--verdict", default="refused", help="verdict recorded for this refusal (default: refused)")
    lp.add_argument("--note", default=None, help="optional free-text note")

    sp = add("show", "print the ledger (oldest first)", cmd_show)
    sp.add_argument("--json", action="store_true", help="print rows as JSONL instead of text")
    sp.add_argument("--tail", type=int, default=None, metavar="N", help="only the last N rows")

    sp = add("count", "tally refusals by rule and lookup", cmd_count)
    sp.add_argument("--rule", default=None, help="count only this rule id")
    sp.add_argument("--lookup", choices=LOOKUPS, default=None, help="count only this lookup result")

    add("verify", "check every row against the schema and the hash chain", cmd_verify)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
