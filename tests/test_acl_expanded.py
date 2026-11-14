"""Synthetic metadata/ACL coverage; no keys, credentials, or tasks are read."""
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linscope.checks import acl
from linscope.core import CommandResult, Context


def bits(value):
    return ''.join(char if value & bit else '-' for char, bit in (('r', 4), ('w', 2), ('x', 1)))


def base_acl(mode):
    return f"user::{bits((mode >> 6) & 7)}\ngroup::{bits((mode >> 3) & 7)}\nother::{bits(mode & 7)}\n"


class FixtureContext(Context):
    def __init__(self, root):
        super().__init__(root=root)
        self.metadata, self.outputs, self.calls, self.reads, self.glob_errors = {}, {}, [], [], {}
        self.make('/', 0o755, directory=True)

    def make(self, path, mode=0o644, uid=0, gid=0, directory=False, socket=False, output=None):
        actual = self.path(path)
        actual.parent.mkdir(parents=True, exist_ok=True)
        if directory:
            actual.mkdir(exist_ok=True)
        elif path != '/':
            actual.write_text('CONTENTS MUST NOT BE READ')
        kind = stat.S_IFDIR if directory else stat.S_IFSOCK if socket else stat.S_IFREG
        self.metadata[path] = SimpleNamespace(st_mode=kind | mode, st_uid=uid, st_gid=gid)
        if output is not None:
            self.outputs[path] = output
        return actual

    def stat(self, path):
        actual = self.path(path).resolve(strict=True)
        relative = actual.relative_to(self.root.resolve())
        canonical = '/' + str(relative) if str(relative) != '.' else '/'
        item = self.metadata.get(canonical)
        if isinstance(item, Exception):
            raise item
        return item or SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)

    def read(self, path, limit=1_048_576):
        self.reads.append(path)
        if path != '/etc/group':
            raise AssertionError('No target/task/credential contents may be read')
        return 'root:x:0:\nshadow:x:42:\n'

    def glob(self, pattern, limit=500):
        if pattern in self.glob_errors:
            raise self.glob_errors[pattern]
        return super().glob(pattern, limit)

    def command(self, argv, timeout=8):
        key = tuple(argv)
        self.calls.append(key)
        if argv[0] == 'getfacl':
            path = argv[-1]
            value = self.outputs.get(path)
            if value is None:
                actual = self.path(path).resolve(strict=True)
                relative = actual.relative_to(self.root.resolve())
                canonical = '/' + str(relative) if str(relative) != '.' else '/'
                value = self.outputs.get(canonical, base_acl(stat.S_IMODE(self.stat(path).st_mode)))
        else:
            value = self.outputs.get(key, '' if argv[1] in ('list-units', 'list-timers') else None)
        if isinstance(value, CommandResult):
            return value
        if isinstance(value, Exception):
            raise value
        return CommandResult(key, 0 if value is not None else 1, value or '', '' if value is not None else 'unavailable')


class ExpandedACLTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ctx = FixtureContext(Path(self.directory.name))
        self.uid = patch('linscope.checks.acl.os.getuid', return_value=1000)
        self.account = patch('linscope.checks.acl.pwd.getpwuid', return_value=SimpleNamespace(pw_dir='/home/alice'))
        self.uid.start(); self.account.start()
        self.addCleanup(self.uid.stop); self.addCleanup(self.account.stop)

    def results(self):
        return {item.id: item for item in acl.run(self.ctx)}

    def one(self, path, number=1):
        return self.results()[acl._id(path, number)]

    def test_host_key_group_read_and_named_read_are_reviewed(self):
        path = '/etc/ssh/ssh_host_ed25519_key'
        self.ctx.make(path, 0o640, gid=42)
        self.assertEqual(self.one(path).status, 'WARN')
        self.ctx.outputs[path] = 'user::rw-\nuser:1000:r--\ngroup::---\nmask::r--\nother::---\n'
        self.assertEqual(self.one(path).status, 'WARN')
        self.assertEqual(self.ctx.reads, [])

    def test_host_key_owner_only_passes(self):
        path = '/etc/ssh/ssh_host_ed25519_key'
        self.ctx.make(path, 0o600)
        findings = self.results()
        self.assertEqual(findings[acl._id(path)].status, 'PASS')
        self.assertEqual(findings[acl._id(path, 3)].status, 'PASS')
        self.assertEqual(self.ctx.reads, [])

    def test_user_credential_owner_and_named_trusted_user_allowed(self):
        path = '/home/alice/.aws/credentials'
        self.ctx.make('/home/alice', 0o750, uid=1000, directory=True)
        self.ctx.make(path, 0o660, uid=1000, gid=1000,
                      output='user::rw-\nuser:1000:rw-\ngroup::---\nmask::rw-\nother::---\n')
        self.assertEqual(self.one(path).status, 'PASS')

    def test_user_credential_named_stranger_effective_read_warns(self):
        path = '/home/alice/.kube/config'
        self.ctx.make(path, 0o640, uid=1000,
                      output='user::rw-\nuser:1001:r--\ngroup::---\nmask::r--\nother::---\n')
        self.assertEqual(self.one(path).status, 'WARN')

    def test_masked_credential_grant_does_not_warn(self):
        path = '/home/alice/.kube/config'
        self.ctx.make(path, 0o600, uid=1000,
                      output='user::rw-\nuser:1001:rw-\ngroup::---\nmask::---\nother::---\n')
        self.assertEqual(self.one(path).status, 'PASS')

    def test_public_authorized_keys_read_is_not_private_key_access(self):
        path = '/home/alice/.ssh/authorized_keys'
        self.ctx.make('/home/alice/.ssh', 0o700, uid=1000, directory=True)
        self.ctx.make(path, 0o644, uid=1000)
        self.ctx.user_paths = [path]
        self.assertEqual(self.one(path).status, 'PASS')

    def test_private_key_discovery_excludes_public_key_files(self):
        private = '/home/alice/.ssh/id_ed25519'
        public = private + '.pub'
        self.ctx.make(private, 0o600, uid=1000)
        self.ctx.make(public, 0o644, uid=1000)
        results = self.results()
        self.assertEqual(results[acl._id(private)].status, 'PASS')
        self.assertNotIn(acl._id(public), results)

    def test_explicit_directory_keeps_private_user_baseline(self):
        path = '/opt/private'
        self.ctx.make(path, 0o700, uid=1000, directory=True)
        self.ctx.user_paths = [path]
        self.assertEqual(self.one(path).status, 'PASS')
        self.ctx.make(path, 0o750, uid=1000, directory=True)
        self.assertEqual(self.one(path).status, 'WARN')

    def test_explicit_missing_path_unknown(self):
        self.ctx.user_paths = ['/missing/private']
        self.assertEqual(self.one('/missing/private').status, 'UNKNOWN')

    def test_explicit_paths_survive_unavailable_home_identity(self):
        path = '/opt/private'
        self.ctx.make(path, 0o600, uid=1000)
        self.ctx.user_paths = [path]
        with patch('linscope.checks.acl.pwd.getpwuid', side_effect=KeyError('unmapped')):
            results = self.results()
        self.assertEqual(results[acl._id(path)].status, 'PASS')
        self.assertEqual(results['ACL-000'].status, 'UNKNOWN')

    def test_discovery_failure_keeps_conventional_credentials(self):
        path = '/home/alice/.aws/credentials'
        self.ctx.make(path, 0o600, uid=1000)
        self.ctx.glob_errors['/home/alice/.ssh/id_*'] = PermissionError('denied')
        results = self.results()
        self.assertEqual(results[acl._id(path)].status, 'PASS')
        self.assertEqual(results['ACL-000'].status, 'UNKNOWN')

    def test_docker_group_write_requires_review(self):
        path = '/var/run/docker.sock'
        self.ctx.make(path, 0o660, gid=999, socket=True)
        self.assertEqual(self.one(path).status, 'WARN')
        self.ctx.make(path, 0o640, gid=999, socket=True)
        self.assertEqual(self.one(path).status, 'PASS')

    def test_docker_named_user_write_requires_review(self):
        path = '/var/run/docker.sock'
        self.ctx.make(path, 0o620, socket=True,
                      output='user::rw-\nuser:1000:-w-\ngroup::---\nmask::-w-\nother::---\n')
        self.assertEqual(self.one(path).status, 'WARN')

    def test_cron_executable_read_execute_is_allowed_write_reviewed(self):
        path = '/etc/cron.daily/example'
        self.ctx.make(path, 0o755)
        self.assertEqual(self.one(path).status, 'PASS')
        self.ctx.make(path, 0o775)
        self.assertEqual(self.one(path).status, 'WARN')
        self.assertEqual(self.ctx.reads, [])

    def test_parent_named_write_warns_even_private_target_passes(self):
        path = '/home/alice/.aws/credentials'
        self.ctx.make('/home/alice', 0o770, uid=1000, directory=True,
                      output='user::rwx\nuser:1001:-w-\ngroup::---\nmask::rwx\nother::---\n')
        self.ctx.make(path, 0o600, uid=1000)
        results = self.results()
        self.assertEqual(results[acl._id(path)].status, 'PASS')
        self.assertEqual(results[acl._id(path, 3)].status, 'WARN')

    def test_parent_named_write_masked_off_is_allowed(self):
        path = '/home/alice/.aws/credentials'
        self.ctx.make('/home/alice', 0o750, uid=1000, directory=True,
                      output='user::rwx\nuser:1001:rwx\ngroup::---\nmask::r-x\nother::---\n')
        self.ctx.make(path, 0o600, uid=1000)
        self.assertEqual(self.one(path, 3).status, 'PASS')

    def test_parent_unknown_is_not_pass_and_positive_warning_survives(self):
        path = '/home/alice/.aws/credentials'
        self.ctx.make(path, 0o600, uid=1000)
        self.ctx.outputs['/home'] = CommandResult((), 1, '', 'denied')
        self.assertEqual(self.one(path, 3).status, 'UNKNOWN')
        self.ctx.make('/home/alice', 0o777, uid=1000, directory=True)
        self.assertEqual(self.one(path, 3).status, 'WARN')

    def test_resolved_symlink_parent_acl_is_checked(self):
        self.ctx.make('/unsafe', 0o777, directory=True)
        self.ctx.make('/unsafe/key', 0o600)
        link = self.ctx.path('/etc/ssh/ssh_host_example_key')
        link.parent.mkdir(parents=True)
        link.symlink_to('../../unsafe/key')
        results = self.results()
        self.assertEqual(results[acl._id('/etc/ssh/ssh_host_example_key')].status, 'PASS')
        self.assertEqual(results[acl._id('/etc/ssh/ssh_host_example_key', 3)].status, 'WARN')

    def test_shared_ancestor_acl_collected_once(self):
        self.ctx.make('/etc/ssh/ssh_host_a_key', 0o600)
        self.ctx.make('/etc/ssh/ssh_host_b_key', 0o600)
        self.results()
        self.assertEqual(self.ctx.calls.count(('getfacl', '-cpn', '--', '/etc')), 1)
        self.assertEqual(self.ctx.calls.count(('getfacl', '-cpn', '--', '/')), 1)

    def test_private_directory_default_acl_review(self):
        path = '/home/alice/.ssh'
        self.ctx.make(path, 0o700, uid=1000, directory=True,
                      output='user::rwx\ngroup::---\nother::---\ndefault:user::rwx\ndefault:group::r-x\ndefault:other::---\n')
        self.assertEqual(self.one(path).status, 'PASS')
        self.assertEqual(self.one(path, 2).status, 'WARN')

    def test_selected_service_fragments_and_dropins_checked(self):
        self.ctx.service_units = ['example.service']
        fragment, dropin = '/usr/lib/systemd/system/example.service', '/etc/systemd/system/example.service.d/hardening.conf'
        self.ctx.make(fragment, 0o644)
        self.ctx.make(dropin, 0o664)
        command = ('systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths', '--', 'example.service')
        self.ctx.outputs[command] = f'LoadState=loaded\nFragmentPath={fragment}\nDropInPaths={dropin}\n'
        results = self.results()
        self.assertEqual(results[acl._id(fragment)].status, 'PASS')
        self.assertEqual(results[acl._id(dropin)].status, 'WARN')
        self.assertTrue(all('Exec' not in ' '.join(call) and 'Environment' not in ' '.join(call) for call in self.ctx.calls))

    def test_user_flag_cannot_weaken_root_cron_or_service_identity(self):
        fragment = '/opt/example.service'
        cron = '/etc/cron.d/example'
        self.ctx.make(fragment, 0o600, uid=1000)
        self.ctx.make(cron, 0o600, uid=1000)
        self.ctx.service_units = ['example.service']
        self.ctx.user_paths = [fragment, cron]
        command = ('systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths', '--', 'example.service')
        self.ctx.outputs[command] = f'LoadState=loaded\nFragmentPath={fragment}\nDropInPaths=\n'
        results = self.results()
        self.assertEqual(results[acl._id(fragment)].status, 'WARN')
        self.assertEqual(results[acl._id(cron)].status, 'WARN')

    def test_user_flag_cannot_weaken_docker_socket_identity(self):
        path = '/var/run/docker.sock'
        self.ctx.make(path, 0o600, uid=1000, socket=True)
        self.ctx.user_paths = [path]
        self.assertEqual(self.one(path).status, 'WARN')

    def test_timer_and_activated_service_fragments_discovered(self):
        timer, service = '/usr/lib/systemd/system/example.timer', '/usr/lib/systemd/system/example.service'
        self.ctx.make(timer, 0o644); self.ctx.make(service, 0o644)
        listing = ('systemctl', 'list-timers', '--all', '--no-legend', '--no-pager')
        self.ctx.outputs[listing] = 'n/a n/a n/a n/a example.timer example.service\n'
        self.ctx.outputs[('systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths,Unit', '--', 'example.timer')] = f'LoadState=loaded\nFragmentPath={timer}\nDropInPaths=\nUnit=example.service\n'
        self.ctx.outputs[('systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths', '--', 'example.service')] = f'LoadState=loaded\nFragmentPath={service}\nDropInPaths=\n'
        results = self.results()
        self.assertEqual(results[acl._id(timer)].status, 'PASS')
        self.assertEqual(results[acl._id(service)].status, 'PASS')

    def test_missing_or_ambiguous_unit_fragment_is_unknown_scope(self):
        self.ctx.service_units = ['example.service']
        command = ('systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths', '--', 'example.service')
        for output in ('LoadState=not-found\nFragmentPath=\nDropInPaths=\n',
                       'LoadState=loaded\nFragmentPath=/a\nFragmentPath=/b\nDropInPaths=\n',
                       'LoadState=loaded\nFragmentPath=\nDropInPaths=\n'):
            with self.subTest(output=output):
                self.ctx.outputs[command] = output
                self.assertEqual(self.results()['ACL-000'].status, 'UNKNOWN')

    def test_escaped_dropins_not_guessed_as_partial_paths(self):
        self.ctx.service_units = ['example.service']
        command = ('systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths', '--', 'example.service')
        self.ctx.outputs[command] = 'LoadState=loaded\nFragmentPath=/valid.service\nDropInPaths=/a\\x20b.conf\n'
        results = self.results()
        self.assertEqual(results['ACL-000'].status, 'UNKNOWN')
        self.assertNotIn(acl._id('/valid.service'), results)

    def test_target_and_parent_limits_are_explicit_unknown(self):
        for number in range(10):
            self.ctx.make(f'/etc/cron.d/job{number}', 0o644)
        with patch('linscope.checks.acl.MAX_TARGETS', 10):
            results = self.results()
        self.assertEqual(results['ACL-000'].status, 'UNKNOWN')
        self.assertIn('Target limit', results['ACL-000'].evidence)
        self.ctx.make('/etc/ssh/ssh_host_key_key', 0o600)
        with patch('linscope.checks.acl.MAX_ANCESTORS', 1):
            results = self.results()
        self.assertEqual(results['ACL-000'].status, 'UNKNOWN')
        self.assertEqual(results[acl._id('/etc/ssh/ssh_host_key_key', 3)].status, 'UNKNOWN')

    def test_acl_error_does_not_hide_discovered_target(self):
        path = '/etc/ssh/ssh_host_ed25519_key'
        self.ctx.make(path, 0o600)
        self.ctx.outputs[path] = CommandResult((), 0, 'user::rw-\ngroup::---\nother::---\n', error='truncated')
        self.assertEqual(self.one(path).status, 'UNKNOWN')

    def test_parent_evidence_survives_unreadable_target_acl(self):
        path = '/etc/ssh/ssh_host_ed25519_key'
        self.ctx.make('/etc/ssh', 0o777, directory=True)
        self.ctx.make(path, 0o600)
        self.ctx.outputs[path] = CommandResult((), 1, '', 'denied')
        results = self.results()
        self.assertEqual(results[acl._id(path)].status, 'UNKNOWN')
        self.assertEqual(results[acl._id(path, 3)].status, 'WARN')

    def test_dangling_optional_key_is_unknown_not_skipped(self):
        path = '/etc/ssh/ssh_host_missing_key'
        link = self.ctx.path(path)
        link.parent.mkdir(parents=True)
        link.symlink_to('missing-target')
        self.assertEqual(self.one(path).status, 'UNKNOWN')

    def test_oversized_acl_entry_set_is_not_partially_evaluated(self):
        text = 'user::rw-\ngroup::---\nother::---\nmask::r--\n'
        text += ''.join(f'user:{number}:r--\n' for number in range(1, acl.MAX_ACL_ENTRIES))
        with self.assertRaisesRegex(ValueError, 'entry limit'):
            acl.parse_acl(text)

    def test_owner_snapshot_change_is_unknown(self):
        path = '/etc/ssh/ssh_host_ed25519_key'
        self.ctx.make(path, 0o600)
        original = self.ctx.command
        def command(argv, timeout=8):
            output = original(argv, timeout)
            if argv[-1] == path:
                self.ctx.metadata[path] = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1001, st_gid=0)
            return output
        self.ctx.command = command
        self.assertEqual(self.one(path).status, 'UNKNOWN')

    def test_acl_ctime_change_is_unknown_even_with_same_mode_and_owner(self):
        path = '/etc/ssh/ssh_host_ed25519_key'
        for field, before, after in (('st_ctime_ns', 100, 200), ('st_ctime', 1.0, 2.0)):
            with self.subTest(field=field):
                self.ctx.make(path, 0o600)
                setattr(self.ctx.metadata[path], field, before)
                original = self.ctx.command
                def command(argv, timeout=8):
                    output = original(argv, timeout)
                    if argv[-1] == path:
                        item = self.ctx.metadata[path]
                        self.ctx.metadata[path] = SimpleNamespace(**{**vars(item), field: after})
                    return output
                self.ctx.command = command
                try:
                    self.assertEqual(self.one(path).status, 'UNKNOWN')
                finally:
                    self.ctx.command = original


if __name__ == '__main__':
    unittest.main()
