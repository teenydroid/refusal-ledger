#!/usr/bin/env python3
"""Tests for refusal_ledger: end-to-end over the real CLI (as a user runs it),
plus tamper, reordering, gap, junk-line and lossy-input cases. Stdlib only."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refusal_ledger as rl

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"


class RefusalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="refusal-test-")
        self.ledger = os.path.join(self.dir, "refusals.jsonl")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def run_cli(self, *args, stdin=None):
        proc = subprocess.run(
            [PY, os.path.join(HERE, "refusal_ledger.py"), *args],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.dir,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")

    def rows(self):
        with open(self.ledger, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def rewrite(self, rows):
        with open(self.ledger, "w", encoding="ascii") as f:
            f.write("".join(json.dumps(r, ensure_ascii=True, separators=(",", ":")) + "\n" for r in rows))

    def set_last_row(self, mutate):
        rows = self.rows()
        mutate(rows[-1])
        self.rewrite(rows)

    def swap_rows(self, a, b):
        rows = self.rows()
        rows[a], rows[b] = rows[b], rows[a]
        self.rewrite(rows)

    # ------------------------------------------------------------ log

    def test_log_records_row_with_rule_and_version(self):
        code, out, err = self.run_cli(
            "log", "--rule", "no-send", "--version", "1.4", "--verdict", "refused",
            "--note", "asked to email a stranger", "--", "send an email to bob",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("logged #1", out)
        self.assertIn("no-send@1.4", out)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["input"], "send an email to bob")
        self.assertEqual(row["rule"], "no-send")
        self.assertEqual(row["rule_version"], "1.4")
        self.assertEqual(row["lookup"], "ok")
        self.assertEqual(row["verdict"], "refused")
        self.assertEqual(row["note"], "asked to email a stranger")
        self.assertEqual(row["seq"], 1)
        self.assertIsNone(row["prev"])
        self.assertEqual(row["hash"], rl.row_hash(row))
        self.assertTrue(row["ts"].endswith("Z"))

    def test_log_appends_without_touching_prior_rows(self):
        self.run_cli("log", "--rule", "r1", "--version", "1", "--", "first no")
        code, _, err = self.run_cli("log", "--rule", "r1", "--version", "2", "--", "second no")
        self.assertEqual(code, 0, err)
        rows = self.rows()
        self.assertEqual([r["seq"] for r in rows], [1, 2])
        self.assertEqual([r["rule_version"] for r in rows], ["1", "2"])
        self.assertEqual(rows[1]["prev"], rows[0]["hash"])
        self.assertEqual(rows[0]["input"], "first no")

    def test_log_versions_of_same_rule_stay_distinguishable(self):
        self.run_cli("log", "--rule", "gate", "--version", "1.0", "--", "no from the old one")
        self.run_cli("log", "--rule", "gate", "--version", "2.0", "--", "no from the new one")
        summary = json.loads(self.run_cli("count", "--rule", "gate")[1])
        self.assertEqual(summary["by_rule"]["gate@1.0"], 1)
        self.assertEqual(summary["by_rule"]["gate@2.0"], 1)

    def test_log_lookup_ok_requires_version(self):
        code, _, err = self.run_cli("log", "--rule", "r", "--", "input")
        self.assertEqual(code, 2)
        self.assertIn("requires --version", err)
        self.assertFalse(os.path.exists(self.ledger))

    def test_log_lookup_miss_forbids_version(self):
        code, _, err = self.run_cli("log", "--rule", "r", "--lookup", "miss", "--version", "9", "--", "input")
        self.assertEqual(code, 2)
        self.assertIn("contradicts", err)
        self.assertFalse(os.path.exists(self.ledger))

    def test_log_lookup_miss_stores_unresolved(self):
        code, out, err = self.run_cli("log", "--rule", "utf8-gate", "--lookup", "miss", "--", "input")
        self.assertEqual(code, 0, err)
        self.assertIn("utf8-gate@(unresolved)", out)
        row = self.rows()[0]
        self.assertIsNone(row["rule_version"])
        self.assertEqual(row["lookup"], "miss")

    def test_log_input_with_newlines_from_argv(self):
        code, _, err = self.run_cli("log", "--rule", "r", "--version", "1", "--", "line one\nline two\r\nline three")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rows()[0]["input"], "line one\nline two\r\nline three")

    def test_log_stdin_strips_one_trailing_newline_only(self):
        code, _, err = self.run_cli("log", "--stdin", "--rule", "r", "--version", "1", stdin=b"exact bytes\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rows()[0]["input"], "exact bytes")
        # a second trailing newline is content: exactly one is stripped
        code, _, err = self.run_cli("log", "--stdin", "--rule", "r", "--version", "1", stdin=b"keep two\n\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.rows()[1]["input"], "keep two\n")

    def test_log_stdin_lossy_utf8_is_recorded(self):
        code, _, err = self.run_cli("log", "--stdin", "--rule", "r", "--lookup", "miss", stdin=b"\xff\xfe raw bytes")
        self.assertEqual(code, 0, err)
        row = self.rows()[0]
        self.assertTrue(row["input_lossy"])
        self.assertEqual(row["lookup"], "miss")

    def test_log_stdin_multibyte_utf8_survives_exactly(self):
        text = "naïve café — for the win 🤖 ok"
        code, _, err = self.run_cli("log", "--stdin", "--rule", "r", "--version", "1", stdin=text.encode("utf-8"))
        self.assertEqual(code, 0, err)
        self.assertFalse(self.rows()[0]["input_lossy"])
        self.assertEqual(self.rows()[0]["input"], text)

    def test_log_empty_input_is_refused(self):
        code, _, err = self.run_cli("log", "--rule", "r", "--version", "1", stdin=b"")
        self.assertEqual(code, 2)
        self.assertIn("empty input", err)

    def test_env_ledger_variable(self):
        env = dict(os.environ, REFUSAL_LEDGER=os.path.join(self.dir, "elsewhere.jsonl"))
        proc = subprocess.run(
            [PY, os.path.join(HERE, "refusal_ledger.py"), "log", "--rule", "r", "--version", "1", "--", "env-input"],
            input=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir, env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertTrue(os.path.exists(os.path.join(self.dir, "elsewhere.jsonl")))

    # --------------------------------------------------- show and count

    def test_show_text_and_json(self):
        self.run_cli("log", "--rule", "a", "--version", "1", "--note", "n1", "--", "in one")
        self.run_cli("log", "--rule", "b", "--lookup", "miss", "--", "in two")
        code, out, err = self.run_cli("show")
        self.assertEqual(code, 0, err)
        self.assertIn("lookup=ok", out)
        self.assertIn("rule=a@1", out)
        self.assertIn("rule=b@(unresolved)", out)
        self.assertIn("in one", out)
        self.assertIn("note: n1", out)
        code, out, err = self.run_cli("show", "--json")
        self.assertEqual(code, 0, err)
        shown = [json.loads(line) for line in out.splitlines() if line.strip()]
        self.assertEqual([r["input"] for r in shown], ["in one", "in two"])

    def test_show_tail(self):
        for i in range(3):
            self.run_cli("log", "--rule", "r", "--version", "1", "--", "no %d" % i)
        code, out, _ = self.run_cli("show", "--tail", "1", "--json")
        self.assertEqual(code, 0)
        rows = [json.loads(line) for line in out.splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["input"], "no 2")

    def test_count_summary_shape(self):
        self.run_cli("log", "--rule", "a", "--version", "1", "--", "x")
        self.run_cli("log", "--rule", "a", "--version", "1", "--", "y")
        self.run_cli("log", "--rule", "b", "--lookup", "miss", "--", "z")
        code, out, err = self.run_cli("count")
        self.assertEqual(code, 0, err)
        summary = json.loads(out)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_rule"], {"a@1": 2, "b@(unresolved)": 1})
        self.assertEqual(summary["by_lookup"], {"ok": 2, "miss": 1})
        code, out, _ = self.run_cli("count", "--lookup", "miss")
        self.assertEqual(json.loads(out)["total"], 1)
        code, out, _ = self.run_cli("count", "--rule", "a")
        self.assertEqual(json.loads(out)["total"], 2)

    def test_commands_on_missing_ledger_are_empty_not_errors(self):
        code, out, err = self.run_cli("verify")
        self.assertEqual(code, 0, err)
        self.assertIn("0 row(s) verified", out)
        code, out, _ = self.run_cli("show")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        code, out, _ = self.run_cli("count")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total"], 0)

    # ---------------------------------------------------------- verify

    def test_verify_passes_on_clean_ledger(self):
        self.run_cli("log", "--rule", "a", "--version", "1", "--", "one")
        self.run_cli("log", "--rule", "b", "--lookup", "miss", "--", "two")
        code, out, err = self.run_cli("verify")
        self.assertEqual(code, 0, err)
        self.assertIn("hash chain intact", out)
        self.assertIn("2 row(s) verified", out)

    def test_verify_detects_edited_input(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "original input")
        self.set_last_row(lambda r: r.update({"input": "rewritten history"}))
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("stored hash does not match row content", out)
        self.assertIn("FAILED", out)

    def test_verify_detects_bumped_version(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "no")
        self.set_last_row(lambda r: r.update({"rule_version": "999"}))
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("stored hash does not match row content", out)

    def test_verify_detects_deleted_row(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "one")
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "two")
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "three")
        rows = self.rows()
        del rows[1]
        self.rewrite(rows)
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("prev does not match the previous row's hash", out)
        self.assertIn("expected seq 2, found 3", out)

    def test_verify_detects_reordering(self):
        for i in range(3):
            self.run_cli("log", "--rule", "r", "--version", "1", "--", "row %d" % i)
        self.swap_rows(0, 1)
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("prev does not match", out)

    def test_verify_detects_seq_gap(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "one")
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "two")
        # rewrite row 2 with a self-consistent hash but a jumped seq
        self.set_last_row(lambda r: r.update({"seq": 4, "hash": rl.row_hash({**r, "seq": 4})}))
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("expected seq 2, found 4", out)
        self.assertIn("FAILED", out)

    def test_verify_detects_bad_lookup_version_pairing(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "no")
        self.set_last_row(lambda r: r.update({"rule_version": None, "hash": rl.row_hash({**r, "rule_version": None})}))
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("lookup ok but rule_version is null", out)

    def test_verify_reports_corrupt_json_line(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "one")
        with open(self.ledger, "a", encoding="ascii") as f:
            f.write("{not json at all\n")
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("not valid JSON", out)
        self.assertIn("FAILED", out)
        # and logging refuses to append to the corrupted ledger
        code2, _, err2 = self.run_cli("log", "--rule", "r", "--version", "1", "--", "new row")
        self.assertEqual(code2, 1)
        self.assertIn("refusing to append", err2)

    def test_verify_reports_unknown_and_missing_fields(self):
        self.run_cli("log", "--rule", "r", "--version", "1", "--", "one")
        self.set_last_row(lambda r: r.update({"extra": "field"}))
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("unknown field(s): extra", out)
        rows = self.rows()
        rows[0].pop("ts")
        self.rewrite(rows)
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("missing field(s): ts", out)

    def test_verify_non_dict_row(self):
        with open(self.ledger, "w", encoding="ascii") as f:
            f.write('["a","list"]\n')
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 1)
        self.assertIn("row is not a JSON object", out)

    def test_row_hash_is_deterministic(self):
        row = {
            "seq": 1, "ts": "2026-11-14T00:00:00.000000Z", "input": "x", "input_lossy": False,
            "rule": "r", "rule_version": "1", "lookup": "ok", "verdict": "refused",
            "note": None, "prev": None,
        }
        h1 = rl.row_hash(row)
        h2 = rl.row_hash(dict(reversed(list(row.items()))))
        self.assertEqual(h1, h2)
        self.assertRegex(h1, r"^[0-9a-f]{64}$")

    def test_rule_ref_display(self):
        self.assertEqual(rl.rule_ref({"rule": "a", "rule_version": "1.4"}), "a@1.4")
        self.assertEqual(rl.rule_ref({"rule": "a", "rule_version": None}), "a@(unresolved)")

    def test_readable_flattens_newlines(self):
        self.assertEqual(rl.readable("a\nb\rc"), "a\\nb\\rc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
