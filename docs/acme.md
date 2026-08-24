# ACME certificate reload profiles

`acme.reload_command` is retained for configuration and API compatibility, but it is no longer a free-form command. `acme.sh` evaluates `--reloadcmd` with a shell, so CheeseWAF accepts only the following closed values:

| Configuration value | Command passed to `acme.sh` |
| --- | --- |
| Empty or `disabled` | None; `--reloadcmd` is omitted |
| `systemd-restart` | `/usr/bin/systemctl restart cheesewaf.service` |
| `/usr/bin/systemctl restart cheesewaf.service` | The same exact command, retained for compatible existing configurations |

The default is disabled. The first certificate issuance is applied by CheeseWAF's in-process site synchronization. Later `acme.sh` renewals replace the certificate files, so operators must choose how renewed certificates become active.

The packaged `cheesewaf.service` runs as the unprivileged `cheesewaf` user and does not grant permission to restart itself. The `systemd-restart` profile must be selected only after the operator has configured and tested a narrowly scoped system service authorization for that account. CheeseWAF does not install that host policy.

## Migration

Existing free-form values such as `systemctl reload cheesewaf`, `/usr/bin/systemctl reload cheesewaf`, scripts, wrappers, custom paths, and commands with extra arguments are rejected during configuration validation, including while ACME is disabled. The packaged unit has no `ExecReload`, so `systemctl reload cheesewaf` was not a working default.

Set `reload_command` to an empty string or `disabled` before upgrading. If the host has an explicitly authorized restart policy, use `systemd-restart` instead. Custom renewal activation should run outside `acme.sh` and outside this field.
