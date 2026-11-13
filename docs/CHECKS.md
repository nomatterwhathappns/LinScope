# Check catalog

Fourteen categories, with stable IDs for both checks and inventory findings. Some
IDs are conditional: SSH-000 replaces unavailable/default-path SSH evaluation.
A numeric ID count is not a measure of coverage or host security. See the module
docstrings and emitted evidence for each check's exact scope.

Select categories using `--category NAME` (repeatable), or list them with
`--list-categories`. All categories run by default.

## ssh

[Implementation](../linscope/checks/ssh.py)

| ID | Scope |
| --- | --- |
| `SSH-000` | Fallback: default configuration absent or effective collection unavailable |
| `SSH-001` | Root SSH login |
| `SSH-002` | Password authentication |
| `SSH-003` | Empty passwords |
| `SSH-004` | Public-key authentication |
| `SSH-005` | Authentication attempt limit |
| `SSH-006` | X11 forwarding |
| `SSH-007` | Forwarded-port bind scope |
| `SSH-008` | Evaluation scope and Match limitations |

## accounts

[Implementation](../linscope/checks/accounts.py)

| ID | Scope |
| --- | --- |
| `ACCT-001` | UID zero accounts |
| `ACCT-002` | Duplicate local UIDs |
| `ACCT-003` | Interactive system accounts |
| `ACCT-004` | Privileged-group inventory |
| `ACCT-005` | Passwordless sudo token review |
| `ACCT-006` | Broad sudo rule inventory |

## permissions

[Implementation](../linscope/checks/permissions.py)

| ID | Scope |
| --- | --- |
| `PERM-001` | passwd metadata |
| `PERM-002` | group metadata |
| `PERM-003` | shadow metadata and trusted group-read GID |
| `PERM-004` | gshadow metadata and trusted group-read GID |
| `PERM-005` | sudoers metadata |
| `PERM-006` | sshd_config metadata |
| `PERM-007` | SSH host private-key metadata |
| `PERM-008` | tmp ownership/type/sticky bit |
| `PERM-009` | var/tmp ownership/type/sticky bit |
| `PERM-010` | Scoped SUID/SGID inventory (--deep) |
| `PERM-011` | Scoped world-writable files (--deep) |

## authentication

[Implementation](../linscope/checks/authentication.py)

| ID | Scope |
| --- | --- |
| `AUTHENTICATION-001` | Password aging creation defaults |
| `AUTHENTICATION-002` | Expiry warning creation default |
| `AUTHENTICATION-003` | PAM quality-module references |
| `AUTHENTICATION-004` | PAM failed-login module references |
| `AUTHENTICATION-005` | Interactive account no-password status |
| `AUTHENTICATION-006` | Existing-account password aging inventory |

## network

[Implementation](../linscope/checks/network.py)

| ID | Scope |
| --- | --- |
| `NETWORK-001` | TCP/UDP listener inventory |
| `NETWORK-002` | Non-loopback binding inventory |
| `NETWORK-003` | Plaintext-service port hints |
| `NETWORK-004` | UFW manager state |
| `NETWORK-005` | IPv4 base INPUT default policy |
| `NETWORK-006` | IPv6 base INPUT default policy |

## services

[Implementation](../linscope/checks/services.py)

| ID | Scope |
| --- | --- |
| `SERVICES-001` | Running services |
| `SERVICES-002` | Enabled services |
| `SERVICES-003` | Selected legacy service/socket names |
| `SERVICES-004` | Failed services |

## kernel

[Implementation](../linscope/checks/kernel.py)

| ID | Scope |
| --- | --- |
| `KERNEL-001` | IPv4 forwarding relative to profile |
| `KERNEL-002` | IPv4 accept redirects (all/default) |
| `KERNEL-003` | IPv4 send redirects (all/default) |
| `KERNEL-004` | IPv6 accept redirects (all/default) |
| `KERNEL-005` | ASLR |
| `KERNEL-006` | Kernel log access |
| `KERNEL-007` | Kernel pointer exposure |
| `KERNEL-008` | Protected symlinks/hardlinks |
| `KERNEL-009` | Unprivileged ptrace |

## packages

[Implementation](../linscope/checks/packages.py)

| ID | Scope |
| --- | --- |
| `PACKAGES-001` | Installed package count |
| `PACKAGES-002` | Local APT metadata freshness |
| `PACKAGES-003` | Cached upgrade simulation |
| `PACKAGES-004` | Reboot-required hint |

## logging

[Implementation](../linscope/checks/logging.py)

| ID | Scope |
| --- | --- |
| `LOGGING-001` | Common logging service activity |
| `LOGGING-002` | Journald persistent-storage configuration |
| `LOGGING-003` | Log directory metadata |
| `LOGGING-004` | Logrotate main configuration metadata |
| `LOGGING-005` | Audit daemon activity |
| `LOGGING-006` | Reported time synchronization |
| `LOGGING-007` | Journald retention-key inventory |

## scheduled

[Implementation](../linscope/checks/scheduled.py)

| ID | Scope |
| --- | --- |
| `SCHEDULED-001` | System crontab metadata and ancestry |
| `SCHEDULED-002` | Conventional cron directory/task metadata |
| `SCHEDULED-003` | Direct absolute root cron executable metadata |
| `SCHEDULED-004` | System timer inventory |
| `SCHEDULED-005` | Timer/service fragment and drop-in metadata |

## filesystem

[Implementation](../linscope/checks/filesystem.py)

| ID | Scope |
| --- | --- |
| `FILESYSTEM-001` | Effective tmp mount restrictions |
| `FILESYSTEM-002` | Effective var/tmp mount restrictions |
| `FILESYSTEM-003` | Effective dev/shm mount restrictions |
| `FILESYSTEM-004` | Temporary directory ownership/sticky bits |
| `FILESYSTEM-005` | fstab metadata |

## mac

[Implementation](../linscope/checks/mac.py)

| ID | Scope |
| --- | --- |
| `MAC-001` | MAC runtime availability |
| `MAC-002` | AppArmor loaded profile modes |
| `MAC-003` | SELinux runtime enforcement |
| `MAC-004` | SELinux persistent configuration |

## Collection limits

Commands normally time out after 8 seconds; package simulation and deep file
searches allow 15 seconds. Collected stdout/stderr and configuration files are
limited to 1 MiB each. Globs cap matches at 500 and inspected directory entries
at 20,000. System timer metadata is limited to 50 units. Truncation, ambiguity,
and failed collection remain visible rather than producing a clean result.

Deep search is optional and limited to documented directories. No full-disk,
remote port, application vulnerability, cloud IAM, or effective ACL scan is
performed. Report scope records category selection and whether deep search ran.

## acl

[Implementation](../linscope/checks/acl.py)

`ACL-<12 uppercase hex>-001` evaluates mask-aware target access for conventional
passwd/group/shadow/gshadow/sudoers/sshd_config and the SSH directory. The target
hash is SHA256 of its absolute path, truncated to twelve uppercase hex digits.
`-002` reviews directory default ACL inheritance. Group membership, parent ACLs,
NFSv4 ACLs, and alternate locations are outside this category.

## sudo

[Implementation](../linscope/checks/sudo.py)

`SUDO-<12 uppercase hex>-001` inventories the evaluated noninteractive listing;
`-002` reviews explicit passwordless grants and `-003` reviews broad ALL grants.
The hash derives from the exact selected username. `SUDO-000` indicates invalid
or unavailable identity scope. Raw command arguments are never stored and no
granted command is executed. No broad privilege-safety PASS is inferred.

## Explicit SSH contexts and custom baselines

`SSHCTX-<12 uppercase hex>-001..007` apply SSH checks to an explicit normalized
connection context; `-000` records a collection failure for that context. The
hash derives from canonical sorted JSON. Default SSH IDs remain unchanged.
Supported baseline options are documented in the README and custom policy
example. Their effective values are included in evidence and report scope.
