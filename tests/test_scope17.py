import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linscope import cli
from linscope.core import Context, Finding
from linscope.policy import validate_paths, validate_policy, validate_service_units
from tests.test_cli_integration import sample


class ExpandedScopeTests(unittest.TestCase):
    def test_service_selections_validate_and_sort(self):
        names = ['worker@instance.service', 'nginx.service', 'escaped\\x2dname.service']
        self.assertEqual(validate_service_units(names), sorted(names))
        for value in ('nginx.service', ['--help'], ['../nginx.service'], ['x.socket'],
                      ['a.service', 'a.service'], ['a.service\n'], ['a' * 256 + '.service'], ['a.service'] * 31):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_service_units(value)

    def test_user_paths_normalize_and_reject_unsafe_selections(self):
        self.assertEqual(validate_paths(['/home/alice/.ssh/./config', '/opt/private']), ['/home/alice/.ssh/config', '/opt/private'])
        for value in ('/home/alice/.ssh', ['relative'], ['/a/../b'], ['/a\x00b'], ['/a\x9bb'],
                      ['/a', '/a/.'], ['/x'] * 51, [None]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_paths(value)

    def test_new_categories_and_policy_fields_accepted(self):
        policy = {'checks': ['systemd', 'docker', 'userfiles'], 'service_units': ['nginx.service'], 'user_paths': ['/opt/private']}
        self.assertEqual(validate_policy(policy), policy)

    def test_cli_explicit_targets_override_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'policy.json')
            path.write_text(json.dumps({'service_units': ['old.service'], 'user_paths': ['/old/private']}))
            with patch('linscope.cli.Context') as context, patch('linscope.cli.collect', return_value=sample()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['--policy', str(path), '--category', 'systemd', '--service-unit', 'new.service', '--user-path', '/new/private']), 0)
            self.assertEqual(context.call_args.kwargs['service_units'], ['new.service'])
            self.assertEqual(context.call_args.kwargs['user_paths'], ['/new/private'])

    def test_invalid_targets_do_not_collect(self):
        for arguments in (['--service-unit', '--help'], ['--service-unit', '../x.service'], ['--user-path', 'relative'], ['--user-path', '/a/../b']):
            with self.subTest(arguments=arguments), patch('linscope.cli.collect') as collect, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    code = cli.main(arguments)
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2)
                collect.assert_not_called()

    def test_real_uid_is_part_of_current_user_scope(self):
        finding = Finding('USERFILE-TEST-001', 'userfiles', 'Fixture', 'INFO', 'info', 'fixture', 'review')
        with patch('linscope.cli.CHECKS', {'userfiles': lambda _: [finding]}), patch('linscope.cli.os.getuid', return_value=1234):
            report = cli.collect(Context(), ['userfiles'])
        self.assertEqual(report['scope']['parameters']['identity_uid'], 1234)

    def test_explicit_sudo_targets_record_target_names(self):
        finding = Finding('SUDO-TEST-001', 'sudo', 'Fixture', 'INFO', 'info', 'fixture', 'review')
        with patch('linscope.cli.CHECKS', {'sudo': lambda _: [finding]}):
            report = cli.collect(Context(sudo_users=['alice']), ['sudo'])
        self.assertEqual(report['scope']['parameters'], {'sudo_users': ['alice']})


if __name__ == '__main__':
    unittest.main()
