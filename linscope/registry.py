"""The explicit built-in registry keeps report scope and releases reproducible."""
from linscope.checks import accounts, authentication, network, permissions, services, ssh

CHECKS = {
    "ssh": ssh.run,
    "accounts": accounts.run,
    "permissions": permissions.run,
    "authentication": authentication.run,
    "network": network.run,
    "services": services.run,
}
