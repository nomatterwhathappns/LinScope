import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linscope.checks import capabilities as caps
from linscope.core import CommandResult


class FakeContext:
    def __init__(self, paths=None, output="", roots=None, probe_error=None,
                 discovery_error=None, batch_outputs=None, deep=False, discovery_result=None):
        self.paths = ["/usr/bin/example"] if paths is None else paths
        self.output = output
        self.roots = {root: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755) for root in caps.ROOTS} if roots is None else roots
        self.probe_error = probe_error
        self.discovery_error = discovery_error
        self.discovery_result = discovery_result
        self.batch_outputs = iter(batch_outputs) if batch_outputs is not None else None
        self.deep = deep
        self.calls = []

    def stat(self, path):
        value = self.roots.get(path, FileNotFoundError(path))
        if isinstance(value, Exception):
            raise value
        return value

    def command(self, argv, timeout=8):
        self.calls.append((tuple(argv), timeout))
        if argv == caps.PROBE_COMMAND:
            return CommandResult(tuple(argv), None if self.probe_error else 0,
                                 error=self.probe_error or "")
        if argv[0] == "find":
            if self.discovery_result is not None:
                return self.discovery_result
            return CommandResult(tuple(argv), 1 if self.discovery_error else 0,
                                 "".join(path + "\0" for path in self.paths), error=self.discovery_error or "")
        output = next(self.batch_outputs) if self.batch_outputs is not None else self.output
        if isinstance(output, CommandResult):
            return output
        return CommandResult(tuple(argv), 0, output)


class CapabilityParsingTests(unittest.TestCase):
    def record(self, text, path="/usr/bin/example"):
        return caps.parse_output(text, [path])[0]

    def test_modern_flags_are_distinct(self):
        record = self.record("/usr/bin/example cap_setuid=ep cap_net_raw+i\n")
        self.assertEqual(record.permitted, {"cap_setuid"})
        self.assertEqual(record.effective, {"cap_setuid"})
        self.assertEqual(record.inheritable, {"cap_net_raw"})

    def test_legacy_output_and_spaces_in_filename(self):
        record = self.record("/usr/bin/example file = cap_setuid+ep\n", "/usr/bin/example file")
        self.assertEqual(record.path, "/usr/bin/example file")
        self.assertEqual(record.permitted, {"cap_setuid"})

    def test_root_id_zero_and_nonzero_preserved(self):
        for value in (0, 1000, 4294967294):
            with self.subTest(value=value):
                record = self.record(f"/usr/bin/example cap_setuid=ep [rootid={value}]\n")
                self.assertEqual(record.rootid, value)

    def test_empty_capability_attribute_is_not_a_clean_host_verdict(self):
        record = self.record("/usr/bin/example = [rootid=0]\n")
        self.assertFalse(record.permitted | record.effective | record.inheritable)
        self.assertEqual(caps._record_finding(record).status, "INFO")

    def test_global_assignment_and_removal(self):
        permitted, effective, inherited, rootid = caps.parse_capability_text("=ep cap_setuid-e cap_net_raw+i")
        self.assertEqual(permitted, set(caps.CAPABILITIES))
        self.assertNotIn("cap_setuid", effective)
        self.assertEqual(inherited, {"cap_net_raw"})
        self.assertIsNone(rootid)

    def test_multiple_names_and_numeric_known_alias(self):
        permitted, effective, inherited, _ = caps.parse_capability_text("cap_setuid,cap_setgid=ep 13+i")
        self.assertEqual(permitted, {"cap_setuid", "cap_setgid"})
        self.assertEqual(effective, permitted)
        self.assertEqual(inherited, {"cap_net_raw"})

    def test_unknown_malformed_or_duplicate_capability_expression_rejected(self):
        invalid = ("", "   ", "cap_setuid=ep\x00", "cap_setuid=ep\x85", "cap_future=ep", "41=ep", "cap_setuid=epa", "cap_setuid+", "cap_setuid=ee",
                   "cap_setuid,7=ep", "all,cap_setuid=ep", "cap_setuid=ep,cap_setgid=ep",
                   "[rootid=0]", "cap_setuid=ep [rootid=-1]", "cap_setuid=ep [rootid=4294967295]")
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                caps.parse_capability_text(value)

    def test_unqueried_duplicate_or_diagnostic_rows_rejected(self):
        for output in ("/other cap_setuid=ep\n", "/usr/bin/example cap_setuid=ep\n/usr/bin/example cap_setgid=ep\n",
                       "/usr/bin/example (Not a regular file)\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                caps.parse_output(output, ["/usr/bin/example"])

    def test_capability_looking_filename_is_resolved_against_queried_paths(self):
        path = "/usr/bin/a cap_setuid=ep"
        record = caps.parse_output(path + " cap_net_raw=ep\n", [path])[0]
        self.assertEqual(record.path, path)
        self.assertEqual(record.permitted, {"cap_net_raw"})
        with self.assertRaises(ValueError):
            caps.parse_output(path + " cap_net_raw=ep\n", [path, "/usr/bin/a"])

    def test_ambiguous_legacy_separator_never_attributes_to_wrong_file(self):
        output = "/usr/bin/example = cap_setuid=ep\n"
        with self.assertRaises(ValueError):
            caps.parse_output(output, ["/usr/bin/example", "/usr/bin/example ="])

    def test_discovery_is_nul_delimited_bounded_to_roots(self):
        self.assertEqual(caps.parse_discovery("/usr/bin/a file\0", ["/usr/bin"]), ["/usr/bin/a file"])
        for output in ("/usr/bin/a", "/usr/bin/a\0\0", "/elsewhere/file\0", "/usr/bin/../x\0",
                       "/usr/bin/a\nfile\0", "/usr/bin/a\0/usr/bin/a\0"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                caps.parse_discovery(output, ["/usr/bin"])

    def test_shallow_discovery_cannot_silently_become_recursive(self):
        with self.assertRaises(ValueError):
            caps.parse_discovery("/usr/bin/nested/file\0", ["/usr/bin"])
        self.assertEqual(caps.parse_discovery("/usr/bin/nested/file\0", ["/usr/bin"], deep=True), ["/usr/bin/nested/file"])


class CapabilityInventoryTests(unittest.TestCase):
    def rows(self, context):
        return {row.id: row for row in caps.run(context)}

    def test_high_impact_grant_warns_without_exploitability_claim(self):
        ctx = FakeContext(output="/usr/bin/example cap_setuid=ep\n")
        rows = self.rows(ctx)
        self.assertEqual(rows["CAPS-000"].status, "INFO")
        result = rows[caps.path_id("/usr/bin/example")]
        self.assertEqual(result.status, "WARN")
        self.assertEqual(result.severity, "high")
        self.assertIn("permitted=cap_setuid", result.evidence)
        self.assertIn("effective=cap_setuid", result.evidence)
        self.assertIn("exploitability were not tested", result.evidence)
        self.assertIn("not proof", result.recommendation)

    def test_low_impact_metadata_and_no_matches_are_inventory_only(self):
        rows = self.rows(FakeContext(output="/usr/bin/example cap_net_bind_service=ep\n"))
        self.assertEqual(rows[caps.path_id("/usr/bin/example")].status, "INFO")
        rows = self.rows(FakeContext(output=""))
        self.assertEqual(list(rows), ["CAPS-000"])
        self.assertEqual(rows["CAPS-000"].status, "INFO")
        self.assertIn("does not establish host-wide safety", rows["CAPS-000"].evidence)

    def test_missing_getcap_is_unknown_before_discovery(self):
        ctx = FakeContext(probe_error="Command unavailable: getcap")
        self.assertEqual(self.rows(ctx)["CAPS-000"].status, "UNKNOWN")
        self.assertEqual(len(ctx.calls), 1)

    def test_empty_executable_directories_still_probe_getcap(self):
        ctx = FakeContext(paths=[])
        self.assertEqual(self.rows(ctx)["CAPS-000"].status, "INFO")
        self.assertEqual([call[0][0] for call in ctx.calls], ["getcap", "find"])

    def test_default_find_is_shallow_and_deep_is_recursive_xdev(self):
        ctx = FakeContext(paths=[])
        self.rows(ctx)
        command, timeout = ctx.calls[1]
        self.assertIn("-H", command)
        self.assertIn("-xdev", command)
        self.assertIn("-maxdepth", command)
        self.assertEqual(timeout, 15)
        deep = FakeContext(paths=[], deep=True)
        self.rows(deep)
        self.assertNotIn("-maxdepth", deep.calls[1][0])
        self.assertIn("-xdev", deep.calls[1][0])

    def test_getcap_argv_is_metadata_only_and_filename_cannot_be_option(self):
        ctx = FakeContext(paths=["/usr/bin/--help name"], output="/usr/bin/--help name cap_net_raw=ep\n")
        rows = self.rows(ctx)
        self.assertEqual(rows["CAPS-000"].status, "INFO")
        self.assertEqual(ctx.calls[2], (("getcap", "-n", "--", "/usr/bin/--help name"), 15))
        self.assertFalse(any(call[0][0] == "/usr/bin/--help name" for call in ctx.calls))

    def test_root_absence_and_permission_failures_remain_explicit(self):
        absent = FakeContext(roots={})
        self.assertEqual(self.rows(absent)["CAPS-000"].status, "SKIP")
        denied = FakeContext(paths=[], roots={"/usr/bin": PermissionError("denied")})
        self.assertEqual(self.rows(denied)["CAPS-000"].status, "UNKNOWN")
        partial = FakeContext(roots={"/usr/bin": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755),
                                     "/usr/sbin": PermissionError("denied")})
        self.assertEqual(self.rows(partial)["CAPS-000"].status, "UNKNOWN")

    def test_discovery_failure_or_partial_output_is_unknown(self):
        ctx = FakeContext(discovery_error="Command output exceeded collection limit")
        self.assertEqual(self.rows(ctx)["CAPS-000"].status, "UNKNOWN")
        self.assertEqual(len(ctx.calls), 2)

    def test_failed_batch_does_not_hide_other_complete_batch_findings(self):
        paths = ["/usr/bin/a", "/usr/bin/b"]
        with patch.object(caps, "BATCH_FILES", 1):
            ctx = FakeContext(paths=paths, batch_outputs=[CommandResult(("getcap",), 1, "/usr/bin/a cap_setuid=ep\n"),
                                                         "/usr/bin/b cap_setgid=ep\n"])
            rows = self.rows(ctx)
        self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")
        self.assertNotIn(caps.path_id("/usr/bin/a"), rows)
        self.assertEqual(rows[caps.path_id("/usr/bin/b")].status, "WARN")

    def test_zero_exit_getcap_diagnostics_are_not_a_clean_inventory(self):
        result = CommandResult(("getcap",), 0, stderr="/usr/bin/example (Permission denied)\n")
        rows = self.rows(FakeContext(batch_outputs=[result]))
        self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")
        self.assertEqual(len(rows), 1)

    def test_positive_metadata_survives_zero_exit_diagnostics(self):
        result = CommandResult(("getcap",), 0, "/usr/bin/example cap_setuid=ep\n", "another candidate disappeared\n")
        rows = self.rows(FakeContext(batch_outputs=[result]))
        self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")
        self.assertEqual(rows[caps.path_id("/usr/bin/example")].status, "WARN")
        self.assertNotIn("another candidate disappeared", rows["CAPS-000"].evidence)

    def test_successful_discovery_with_diagnostics_remains_incomplete(self):
        result = CommandResult(("find",), 0, "/usr/bin/example\0", "some metadata unavailable")
        rows = self.rows(FakeContext(discovery_result=result, output="/usr/bin/example cap_setuid=ep\n"))
        self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")
        self.assertEqual(rows[caps.path_id("/usr/bin/example")].status, "WARN")

    def test_malformed_unknown_capability_batch_not_reported_clean(self):
        for output in ("/usr/bin/example cap_future=ep\n", "/usr/bin/example cap_setuid=ep [rootid=4294967295]\n"):
            with self.subTest(output=output):
                rows = self.rows(FakeContext(output=output))
                self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")

    def test_candidate_limit_is_visible_and_only_bounded_files_queried(self):
        with patch.object(caps, "MAX_FILES", 1):
            ctx = FakeContext(paths=["/usr/bin/a", "/usr/bin/b"], output="/usr/bin/a cap_setuid=ep\n")
            rows = self.rows(ctx)
        self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")
        self.assertEqual(ctx.calls[2][0][-1], "/usr/bin/a")
        self.assertNotIn("/usr/bin/b", ctx.calls[2][0])

    def test_record_limit_is_visible_and_preserves_sorted_findings(self):
        with patch.object(caps, "MAX_FINDINGS", 1):
            ctx = FakeContext(paths=["/usr/bin/a", "/usr/bin/b"], output="/usr/bin/b cap_setgid=ep\n/usr/bin/a cap_setuid=ep\n")
            rows = self.rows(ctx)
        self.assertEqual(rows["CAPS-000"].status, "UNKNOWN")
        self.assertIn(caps.path_id("/usr/bin/a"), rows)
        self.assertNotIn(caps.path_id("/usr/bin/b"), rows)

    def test_batches_are_bounded_by_count_and_argument_bytes(self):
        paths = ["/usr/bin/" + str(index) + "x" * 100 for index in range(300)]
        batches = list(caps._batches(paths))
        self.assertEqual([path for batch in batches for path in batch], paths)
        self.assertTrue(all(len(batch) <= caps.BATCH_FILES for batch in batches))
        self.assertTrue(all(sum(len(path.encode()) + 9 for path in batch) + 32 <= caps.MAX_ARGUMENT_BYTES for batch in batches))

    def test_stable_path_id_does_not_depend_on_inventory_order(self):
        self.assertEqual(caps.path_id("/usr/bin/example"), caps.path_id("/usr/bin/example"))
        self.assertRegex(caps.path_id("/usr/bin/example"), r"^CAPS-[0-9A-F]{12}-001$")
        self.assertNotEqual(caps.path_id("/usr/bin/example"), caps.path_id("/usr/bin/other"))


if __name__ == "__main__":
    unittest.main()
