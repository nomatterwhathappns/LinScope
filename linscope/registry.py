"""The explicit built-in registry keeps report scope and releases reproducible."""
from linscope.checks import accounts, authentication, filesystem, kernel, logging, mac, network, packages, permissions, scheduled, services, ssh

CHECKS = {
    "ssh": ssh.run,
    "accounts": accounts.run,
    "permissions": permissions.run,
    "authentication": authentication.run,
    "network": network.run,
    "services": services.run,
    "kernel": kernel.run,
    "packages": packages.run,
    "logging": logging.run,
    "scheduled": scheduled.run,
    "filesystem": filesystem.run,
    "mac": mac.run,
}
