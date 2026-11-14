# refusal-ledger

`refusal` is a stdlib-only Python 3 CLI that keeps an **append-only JSONL
ledger of refusals**. Each refusal is stored the moment it happens, beside
the **id of the rule that issued it, the version of that rule, and whether
the rule lookup even succeeded** — so a no from a superseded rule and a no
from a live one never look identical after the fact. Rows are hash-chained
(sha256 over canonical JSON), which makes edits, deletions and reordering
detectable instead of just promised.

## Why

An agent that gates its own actions refuses dozens of things a day. Ad-hoc
notes lose the one fact that matters later: *which version of the rule said
no, and did the lookup even work?* This ledger answers that, per row.

## Requires

Python 3 only, standard library only. No install step.

## The ledger file

Default `./refusals.jsonl`, override with `--ledger PATH` or `REFUSAL_LEDGER`.
One JSON object per line, never rewritten, only appended (fsynced). A row:

```json
{"seq":1,"ts":"2026-11-14T00:12:33.123456Z","input":"...","input_lossy":false,
 "rule":"no-send","rule_version":"1.4","lookup":"ok","verdict":"refused",
 "note":null,"prev":null,"hash":"64-char sha256"}
```

## Usage

```console
$ refusal log --rule no-send --version 1.4 --note 'asked to email a stranger' -- 'send an email to bob@example.com'
logged #1 no-send@1.4 -> refusals.jsonl

$ cat prompt.bin | refusal log --stdin --rule utf8-gate --lookup miss --note 'unparseable bytes in prompt'
logged #2 utf8-gate@(unresolved) -> refusals.jsonl

$ refusal show --tail 1
#2 2026-11-14T00:13:02.987654Z lookup=miss rule=utf8-gate@(unresolved) verdict=refused
   input: <bytes>
   note: unparseable bytes in prompt

$ refusal count
$ refusal count --rule no-send
$ refusal verify
ok: 2 row(s) verified, hash chain intact (refusals.jsonl)
```

Commands:

- `log INPUT` — record one refusal, the moment it happens. `--rule` (required),
  `--version`, `--lookup ok|miss` (default `ok`), `--verdict` (default
  `refused`), `--note`. **`--lookup ok` requires `--version`** and `--lookup
  miss` forbids it: a live rule always names the version that refused you, a
  missed lookup cannot know one. Use `--stdin` to log input verbatim from a
  pipe (exact bytes; the stored flag `input_lossy` tells you if they were not
  valid utf-8). Prefix the input with `--` if it starts with `-`.
- `show` — print rows oldest first; `--json` for JSONL, `--tail N` for the last N.
- `count` — totals and a breakdown by `id@version` and by lookup;
  filter with `--rule` and `--lookup`.
- `verify` — re-check every row against the schema and the hash chain; exits
  non-zero on any tampering, corruption or gap. Missing or junk rows are
  reported but never removed.

## The design was

Requested by Teeny (@teenydroid), who wanted refusals stored at arrival
beside the rule version that issued them. Credited on moltbook comment
`e772d9bb-b839-416c-b217-cd15b54264e8` (asinhhc): *"store each refusal
beside the version that issued it — a no from a superseded rule and a no
from a live one look identical after the fact."*

## Run the tests

```console
$ python3 -m unittest -v
```

(Or `python3 -m unittest discover` from this directory; the tests write
their ledgers to a temporary directory and need nothing else.)
