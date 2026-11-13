import unittest

from linscope.checks import systemd
from linscope.core import CommandResult


def property_text(**overrides):
    values = {
        "Id": "web.service", "LoadState": "loaded", "ActiveState": "active",
        "User": "web", "DynamicUser": "no", "NoNewPrivileges": "yes",
        "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
        "CapabilityBoundingSet": "", "RestrictSUIDSGID": "yes",
    }
    values.update(overrides)
    return "\n".join(f"{key}={value}" for key, value in values.items() if value is not None) + "\n"


class FakeContext:
    profile = "server"

    def __init__(self, selected=None, listing=None, props=None):
        self.service_units = [] if selected is None else selected
        self.listing = "web.service loaded active running Web service\n" if listing is None else listing
        self.props = {"web.service": property_text()} if props is None else props
        self.calls = []

    def command(self, argv):
        self.calls.append(tuple(argv))
        if argv == systemd.LIST_COMMAND:
            if isinstance(self.listing, CommandResult):
                return self.listing
            return CommandResult(tuple(argv), 0, self.listing)
        if argv[:2] == ["systemctl", "show"]:
            value = self.props.get(argv[-1])
            if isinstance(value, CommandResult):
                return value
            if value is not None:
                return CommandResult(tuple(argv), 0, value)
        return CommandResult(tuple(argv), None, error="Unavailable fixture command")


class SystemdTests(unittest.TestCase):
    def unit_findings(self, ctx, name="web.service"):
        return {f.id.rsplit("-", 1)[1]: f for f in systemd.run(ctx) if f.id.startswith(systemd.unit_id(name, 1).rsplit("-", 1)[0] + "-")}

    def test_hardened_unit_is_evaluated_with_read_only_properties(self):
        ctx = FakeContext()
        result = self.unit_findings(ctx)
        self.assertEqual(len(result), 7)
        self.assertEqual(result["001"].status, "INFO")
        self.assertTrue(all(f.status == "PASS" for key, f in result.items() if key != "001"))
        self.assertEqual(ctx.calls[-1], tuple(systemd.show_command("web.service")))
        self.assertNotIn("Environment", " ".join(ctx.calls[-1]))
        self.assertNotIn("ExecStart", " ".join(ctx.calls[-1]))

    def test_root_execution_is_inventory_not_failure(self):
        for user in ("root", "0", "", "000"):
            with self.subTest(user=user):
                result = self.unit_findings(FakeContext(props={"web.service": property_text(User=user)}))
                self.assertEqual(result["001"].status, "INFO")
                self.assertIn("root", result["001"].evidence)

    def test_dynamic_identity_is_not_treated_as_missing(self):
        result = self.unit_findings(FakeContext(props={"web.service": property_text(User="", DynamicUser="yes")}))
        self.assertEqual(result["001"].status, "INFO")
        self.assertIn("dynamic-user handling requested", result["001"].evidence)

    def test_dynamicuser_does_not_prove_a_new_identity_was_allocated(self):
        result = self.unit_findings(FakeContext(props={"web.service": property_text(User="root", DynamicUser="yes")}))
        self.assertEqual(result["001"].status, "INFO")
        self.assertIn("existing-account resolution was not inspected", result["001"].evidence)

    def test_disabled_controls_request_review(self):
        text = property_text(NoNewPrivileges="no", ProtectSystem="no", ProtectHome="no",
                             PrivateTmp="no", RestrictSUIDSGID="no")
        result = self.unit_findings(FakeContext(props={"web.service": text}))
        for number in ("002", "003", "004", "005", "007"):
            self.assertEqual(result[number].status, "WARN")

    def test_partial_protectsystem_is_not_full_baseline(self):
        result = self.unit_findings(FakeContext(props={"web.service": property_text(ProtectSystem="yes")}))
        self.assertEqual(result["003"].status, "WARN")

    def test_semantic_non_boolean_values_are_supported(self):
        text = property_text(ProtectSystem="full", ProtectHome="read-only", PrivateTmp="disconnected")
        result = self.unit_findings(FakeContext(props={"web.service": text}))
        for number in ("003", "004", "005"):
            self.assertEqual(result[number].status, "PASS")
        result = self.unit_findings(FakeContext(props={"web.service": property_text(ProtectHome="tmpfs")}))
        self.assertEqual(result["004"].status, "PASS")

    def test_missing_and_unknown_properties_are_unknown(self):
        missing = property_text(NoNewPrivileges=None, ProtectSystem=None, ProtectHome=None,
                                PrivateTmp=None, CapabilityBoundingSet=None, RestrictSUIDSGID=None)
        result = self.unit_findings(FakeContext(props={"web.service": missing}))
        self.assertTrue(all(f.status == "UNKNOWN" for number, f in result.items() if number != "001"))
        invalid = property_text(NoNewPrivileges="maybe", ProtectSystem="impossible", DynamicUser="maybe")
        result = self.unit_findings(FakeContext(props={"web.service": invalid}))
        self.assertEqual(result["001"].status, "UNKNOWN")
        self.assertEqual(result["002"].status, "UNKNOWN")
        self.assertEqual(result["003"].status, "UNKNOWN")

    def test_missing_identity_user_does_not_default_to_root(self):
        result = self.unit_findings(FakeContext(props={"web.service": property_text(User=None)}))
        self.assertEqual(result["001"].status, "UNKNOWN")

    def test_high_impact_capabilities_request_review_without_claiming_effective_grant(self):
        text = property_text(CapabilityBoundingSet="CAP_NET_BIND_SERVICE CAP_SYS_ADMIN cap_setuid")
        result = self.unit_findings(FakeContext(props={"web.service": text}))["006"]
        self.assertEqual(result.status, "WARN")
        self.assertEqual(result.severity, "high")
        self.assertIn("cap_sys_admin", result.evidence)
        self.assertIn("does not prove", result.evidence)

    def test_restricted_nonempty_capability_set_is_inventory(self):
        result = self.unit_findings(FakeContext(props={"web.service": property_text(CapabilityBoundingSet="cap_net_bind_service")}))
        self.assertEqual(result["006"].status, "INFO")

    def test_unknown_capability_representation_is_unknown(self):
        for caps in ("~cap_sys_admin", "all", "CAP_SYS_ADMIN ?"):
            with self.subTest(caps=caps):
                result = self.unit_findings(FakeContext(props={"web.service": property_text(CapabilityBoundingSet=caps)}))
                self.assertEqual(result["006"].status, "UNKNOWN")

    def test_failed_property_collection_does_not_erase_other_unit_results(self):
        ctx = FakeContext(selected=["web.service", "bad.service"], props={
            "web.service": property_text(),
            "bad.service": CommandResult((), 1, property_text(), "sensitive raw stderr"),
        })
        findings = systemd.run(ctx)
        self.assertEqual(len(findings), 15)
        bad = [f for f in findings if f.id.startswith(systemd.unit_id("bad.service", 1).rsplit("-", 1)[0])]
        self.assertTrue(all(f.status == "UNKNOWN" for f in bad))
        self.assertTrue(all("sensitive raw stderr" not in f.evidence for f in findings))
        self.assertEqual(self.unit_findings(ctx)["002"].status, "PASS")

    def test_nonloaded_unit_default_properties_cannot_pass(self):
        for load in (None, "not-found", "error", "masked"):
            with self.subTest(load=load):
                result = self.unit_findings(FakeContext(props={"web.service": property_text(LoadState=load)}))
                self.assertTrue(all(f.status == "UNKNOWN" for f in result.values()))

    def test_malformed_duplicate_or_unexpected_property_rejects_snapshot(self):
        for suffix in ("NoNewPrivileges=yes\n", "Environment=DO_NOT_COLLECT\n", "malformed\n"):
            with self.subTest(suffix=suffix):
                result = self.unit_findings(FakeContext(props={"web.service": property_text() + suffix}))
                self.assertTrue(all(f.status == "UNKNOWN" for f in result.values()))

    def test_inactive_explicit_service_can_have_valid_configured_properties(self):
        ctx = FakeContext(selected=["web.service"], props={"web.service": property_text(ActiveState="inactive")})
        result = self.unit_findings(ctx)
        self.assertEqual(result["002"].status, "PASS")
        self.assertIn("inactive", result["002"].evidence)
        self.assertFalse(any(call == tuple(systemd.LIST_COMMAND) for call in ctx.calls))

    def test_property_unit_alias_is_explicit(self):
        result = self.unit_findings(FakeContext(selected=["web.service"], props={"web.service": property_text(Id="web-canonical.service")}))
        self.assertEqual(result["002"].status, "PASS")
        self.assertIn("resolved=web-canonical.service", result["002"].evidence)

    def test_invalid_activity_state_rejects_snapshot(self):
        result = self.unit_findings(FakeContext(props={"web.service": property_text(ActiveState="impossible")}))
        self.assertTrue(all(f.status == "UNKNOWN" for f in result.values()))

    def test_discovery_failure_reports_incomplete_scope(self):
        ctx = FakeContext(listing=CommandResult((), 1, "", "Failed to connect to bus"))
        result = systemd.run(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status, "UNKNOWN")

    def test_empty_successful_inventory_is_info_not_security_pass(self):
        result = systemd.run(FakeContext(listing=""))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].status, "INFO")

    def test_partial_or_contradictory_inventory_is_retained_as_unknown(self):
        listing = "web.service loaded active running Web\nbad.service loaded inactive dead Bad\ninvalid row\n"
        result = systemd.run(FakeContext(listing=listing))
        self.assertEqual(result[0].status, "UNKNOWN")
        self.assertEqual(len(result), 8)

    def test_inventory_is_bounded_and_marks_omission(self):
        names = [f"unit{index:02}.service" for index in range(35)]
        listing = "".join(f"{name} loaded active running Unit\n" for name in names)
        ctx = FakeContext(listing=listing, props={name: property_text(Id=name) for name in names})
        result = systemd.run(ctx)
        self.assertEqual(result[0].status, "UNKNOWN")
        self.assertEqual(len(result), 1 + 30 * 7)
        self.assertEqual(len(ctx.calls), 31)
        self.assertIn("35", result[0].evidence)

    def test_explicit_invalid_names_never_become_arguments(self):
        for invalid in ("--help.service", "../bad.service", "/etc/test.service", "web.service\nother.service", "x.socket", "", 7):
            with self.subTest(invalid=invalid):
                ctx = FakeContext(selected=[invalid])
                result = systemd.run(ctx)
                self.assertEqual(result[0].status, "UNKNOWN")
                self.assertFalse(ctx.calls)

    def test_duplicate_selections_are_deduplicated(self):
        ctx = FakeContext(selected=["web.service", "web.service"])
        result = systemd.run(ctx)
        self.assertEqual(len(result), 8)
        self.assertEqual(len(ctx.calls), 1)

    def test_ids_stay_stable_across_selection_order(self):
        props = {"web.service": property_text(), "db.service": property_text(Id="db.service")}
        first = systemd.run(FakeContext(selected=["web.service", "db.service"], props=props))
        second = systemd.run(FakeContext(selected=["db.service", "web.service"], props=props))
        self.assertEqual([f.id for f in first], [f.id for f in second])
        self.assertNotEqual(systemd.unit_id("web.service", 1), systemd.unit_id("db.service", 1))

    def test_container_scope_is_explicit(self):
        ctx = FakeContext()
        ctx.profile = "container"
        result = self.unit_findings(ctx)
        self.assertIn("not the container host", result["002"].evidence)


if __name__ == "__main__":
    unittest.main()
