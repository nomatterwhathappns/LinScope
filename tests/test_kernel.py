import unittest

from linscope.checks import kernel


class FakeContext:
    profile = "server"

    def __init__(self):
        self.values = {
            "/proc/sys/net/ipv4/ip_forward": "0\n",
            "/proc/sys/net/ipv4/conf/all/accept_redirects": "0",
            "/proc/sys/net/ipv4/conf/default/accept_redirects": "0",
            "/proc/sys/net/ipv4/conf/all/send_redirects": "0",
            "/proc/sys/net/ipv4/conf/default/send_redirects": "0",
            "/proc/sys/net/ipv6/conf/all/accept_redirects": "0",
            "/proc/sys/net/ipv6/conf/default/accept_redirects": "0",
            "/proc/sys/kernel/randomize_va_space": "2",
            "/proc/sys/kernel/dmesg_restrict": "1",
            "/proc/sys/kernel/kptr_restrict": "2",
            "/proc/sys/fs/protected_symlinks": "1",
            "/proc/sys/fs/protected_hardlinks": "1",
            "/proc/sys/kernel/yama/ptrace_scope": "1",
        }

    def read(self, path):
        result = self.values.get(path, FileNotFoundError(path))
        if isinstance(result, Exception):
            raise result
        return result


class KernelTests(unittest.TestCase):
    def findings(self, ctx):
        return {f.id: f for f in kernel.run(ctx)}

    def test_expected_live_values_pass(self):
        findings = self.findings(FakeContext())
        self.assertEqual(9, len(findings))
        self.assertTrue(all(f.status == "PASS" for f in findings.values()))

    def test_router_profile_changes_forwarding_expectation(self):
        ctx = FakeContext()
        ctx.values["/proc/sys/net/ipv4/ip_forward"] = "1"
        self.assertEqual("WARN", self.findings(ctx)["KERNEL-001"].status)
        ctx.profile = "router"
        self.assertEqual("PASS", self.findings(ctx)["KERNEL-001"].status)

    def test_missing_or_unreadable_never_pass(self):
        for value in (FileNotFoundError("disabled?"), PermissionError("denied"), "bad"):
            with self.subTest(value=value):
                ctx = FakeContext()
                ctx.values["/proc/sys/kernel/dmesg_restrict"] = value
                self.assertEqual("UNKNOWN", self.findings(ctx)["KERNEL-006"].status)

    def test_partial_aggregate_evidence_is_unknown(self):
        ctx = FakeContext()
        del ctx.values["/proc/sys/fs/protected_hardlinks"]
        self.assertEqual("UNKNOWN", self.findings(ctx)["KERNEL-008"].status)

    def test_container_evidence_limits_host_claim(self):
        ctx = FakeContext()
        ctx.profile = "container"
        self.assertIn("namespace", self.findings(ctx)["KERNEL-001"].evidence)

    def test_invalid_sysctl_does_not_pass(self):
        ctx = FakeContext()
        ctx.values["/proc/sys/kernel/yama/ptrace_scope"] = "9"
        self.assertEqual("WARN", self.findings(ctx)["KERNEL-009"].status)


if __name__ == "__main__":
    unittest.main()
