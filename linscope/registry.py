"""The explicit built-in registry keeps report scope and releases reproducible."""
from linscope.checks import accounts, permissions, ssh

CHECKS = {
    "ssh": ssh.run,
    "accounts": accounts.run,
    "permissions": permissions.run,
}
