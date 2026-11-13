import json
import stat
from types import SimpleNamespace
import unittest

from linscope.checks import docker
from linscope.core import CommandResult

CID = "a" * 64


def container(**changes):
    value = {"Privileged": False, "NetworkMode": "bridge", "ReadonlyRootfs": True,
             "CapAdd": None, "User": "1000", "Mounts": []}
    value.update(changes)
    return value


class FakeContext:
    profile = "server"
    def __init__(self, config=None, inventory=CID + "\n", mode=0o660, uid=0, gid=999, socket=None, command_error=None):
        self.config = container() if config is None else config
        self.inventory, self.mode, self.uid, self.gid = inventory, mode, uid, gid
        self.socket = socket
        self.command_error = command_error
        self.calls = []

    def stat(self, path):
        if self.socket is not None:
            if isinstance(self.socket, Exception):
                raise self.socket
            return self.socket
        return SimpleNamespace(st_mode=stat.S_IFSOCK | self.mode, st_uid=self.uid, st_gid=self.gid)

    def command(self, argv):
        self.calls.append(tuple(argv))
        if self.command_error:
            return CommandResult(tuple(argv), 1, stderr=self.command_error)
        if argv == docker.LIST_ARGS:
            return CommandResult(tuple(argv), 0, self.inventory)
        value = self.config if isinstance(self.config, str) else json.dumps(self.config)
        return CommandResult(tuple(argv), 0, value)


class DockerTests(unittest.TestCase):
    def checks(self, ctx=None):
        return {finding.id: finding for finding in docker.run(ctx or FakeContext())}

    def row(self, values, suffix):
        return values[docker.container_prefix(CID) + suffix]

    def test_safe_projected_container_and_default_socket_group_review(self):
        values = self.checks()
        self.assertEqual(values["DOCKER-001"].status, "WARN")
        self.assertEqual(values["DOCKER-002"].status, "INFO")
        for suffix in ("-001", "-003", "-004", "-005", "-006"):
            self.assertEqual(self.row(values, suffix).status, "PASS")

    def test_no_socket_skips_without_querying_docker(self):
        ctx = FakeContext(socket=FileNotFoundError("missing"))
        values = self.checks(ctx)
        self.assertEqual(values["DOCKER-001"].status, "SKIP")
        self.assertEqual(ctx.calls, [])

    def test_denied_metadata_is_unknown_without_query(self):
        ctx = FakeContext(socket=PermissionError("denied"))
        values = self.checks(ctx)
        self.assertEqual(values["DOCKER-001"].status, "UNKNOWN")
        self.assertEqual(ctx.calls, [])

    def test_regular_socket_path_is_not_contacted(self):
        ctx = FakeContext(socket=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0))
        self.assertEqual(self.checks(ctx)["DOCKER-001"].status, "FAIL")
        self.assertEqual(ctx.calls, [])

    def test_world_writable_socket_fails(self):
        self.assertEqual(self.checks(FakeContext(mode=0o666))["DOCKER-001"].status, "FAIL")

    def test_unknown_namespace_owner_is_not_rootful_pass(self):
        ctx = FakeContext(uid=65534)
        ctx.profile = "container"
        self.assertEqual(self.checks(ctx)["DOCKER-001"].status, "UNKNOWN")

    def test_daemon_failure_is_unknown(self):
        values = self.checks(FakeContext(command_error="permission denied"))
        self.assertEqual(values["DOCKER-002"].status, "UNKNOWN")

    def test_empty_inventory_is_information(self):
        ctx = FakeContext(inventory="")
        values = self.checks(ctx)
        self.assertEqual(values["DOCKER-002"].status, "INFO")
        self.assertEqual(len(ctx.calls), 1)

    def test_malformed_or_duplicate_inventory_never_clean(self):
        for listing in ("short-id\n", CID + "\n" + CID + "\n", "-option\n"):
            with self.subTest(listing=listing):
                ctx = FakeContext(inventory=listing)
                self.assertEqual(self.checks(ctx)["DOCKER-002"].status, "UNKNOWN")
                self.assertEqual(len(ctx.calls), 1)

    def test_inventory_limit_is_visible_and_inspection_bounded(self):
        ids = [f"{number:064x}" for number in range(30)]
        ctx = FakeContext(inventory="\n".join(ids))
        self.assertEqual(self.checks(ctx)["DOCKER-002"].status, "UNKNOWN")
        self.assertEqual(len(ctx.calls), 26)

    def test_fixed_local_endpoint_and_only_projected_fields(self):
        ctx = FakeContext()
        self.checks(ctx)
        for call in ctx.calls:
            self.assertEqual(call[:3], tuple(docker.PREFIX))
        inspection = ctx.calls[1]
        self.assertIn("--format", inspection)
        self.assertNotIn("Env", inspection[inspection.index("--format") + 1])
        self.assertNotIn(".Config}}", docker.PROJECTION)

    def test_known_risky_flags_are_reviewed(self):
        values = self.checks(FakeContext(config=container(Privileged=True, NetworkMode="host", ReadonlyRootfs=False, CapAdd=["CAP_SYS_ADMIN"])))
        for suffix in ("-001", "-002", "-003", "-004"):
            self.assertEqual(self.row(values, suffix).status, "WARN")

    def test_boolean_strings_are_unknown(self):
        values = self.checks(FakeContext(config=container(Privileged="false", ReadonlyRootfs="true")))
        self.assertEqual(self.row(values, "-001").status, "UNKNOWN")
        self.assertEqual(self.row(values, "-003").status, "UNKNOWN")

    def test_nonroot_name_does_not_prove_numeric_nonroot(self):
        self.assertEqual(self.row(self.checks(FakeContext(config=container(User="app"))), "-006").status, "INFO")
        for user in ("", "0", "root", "00", "000:1000"):
            with self.subTest(user=user):
                self.assertEqual(self.row(self.checks(FakeContext(config=container(User=user))), "-006").status, "WARN")

    def test_numeric_uid_range_checked(self):
        self.assertEqual(self.row(self.checks(FakeContext(config=container(User="4294967295"))), "-006").status, "UNKNOWN")

    def test_selected_sensitive_bind_mounts_but_not_ordinary_data(self):
        ordinary = {"Type": "bind", "Source": "/srv/app", "Destination": "/data", "RW": True}
        value = container(Mounts=[ordinary])
        self.assertEqual(self.row(self.checks(FakeContext(config=value)), "-005").status, "PASS")
        for source in ("/", "//", "/etc", "/etc/", "/etc/shadow", "/var/run/docker.sock", "/root/.ssh"):
            with self.subTest(source=source):
                value = container(Mounts=[dict(ordinary, Source=source, RW=False)])
                finding = self.row(self.checks(FakeContext(config=value)), "-005")
                self.assertEqual(finding.status, "WARN")
                self.assertEqual(finding.severity, "medium")

    def test_invalid_projection_or_field_unknown(self):
        for config in ("not-json", "[]"):
            values = self.checks(FakeContext(config=config))
            self.assertEqual(self.row(values, "-000").status, "UNKNOWN")
        values = self.checks(FakeContext(config=container(CapAdd=["UNKNOWN_CAP"], Mounts=[{"Source": "/"}])))
        self.assertEqual(self.row(values, "-004").status, "UNKNOWN")
        self.assertEqual(self.row(values, "-005").status, "UNKNOWN")

    def test_duplicate_projection_keys_and_nonfinite_json_are_unknown(self):
        for raw in ('{"Privileged":true,"Privileged":false}', '{"Privileged":NaN}'):
            with self.subTest(raw=raw):
                self.assertEqual(self.row(self.checks(FakeContext(config=raw)), "-000").status, "UNKNOWN")

    def test_unknown_mount_type_does_not_hide_sensitive_bind(self):
        value = container(Mounts=[{"Type": "BIND", "Source": "/", "Destination": "/host", "RW": True}])
        self.assertEqual(self.row(self.checks(FakeContext(config=value)), "-005").status, "UNKNOWN")

    def test_malformed_network_mode_unknown(self):
        self.assertEqual(self.row(self.checks(FakeContext(config=container(NetworkMode="host\x00"))), "-002").status, "UNKNOWN")

    def test_stable_id_independent_of_inventory_order(self):
        other = "b" * 64
        first = self.checks(FakeContext(inventory=CID + "\n" + other))
        second = self.checks(FakeContext(inventory=other + "\n" + CID))
        self.assertEqual(set(first), set(second))


if __name__ == "__main__":
    unittest.main()
