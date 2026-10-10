# univention-arch-connector

Join Arch Linux (and Arch-based distributions: CachyOS, EndeavourOS, Manjaro, ...)
clients into a [Univention Corporate Server (UCS)](https://www.univention.com/)
domain, with the same feature set that Ubuntu/Linux Mint clients get from
Univention's official [`univention-domain-join`](https://github.com/univention/univention-domain-join).

This is an **unofficial, community port** — see [NOTICE.md](NOTICE.md) for
attribution and licensing. Not affiliated with Univention GmbH.

## What it does

When you join a client to the domain, the tool:

- verifies the domain controller's SSH host key (`--dc-fingerprint`, or an
  interactive confirmation) before sending it any credentials
- creates an LDAP computer object for this machine on the UCS domain controller
- fetches the UCS root CA over that verified SSH connection and trusts it
- writes `/etc/ldap/ldap.conf` and a machine account secret
- configures Kerberos (`/etc/krb5.conf`)
- configures SSSD for identity lookup (LDAP) and authentication (Kerberos)
- adds `sss` to `/etc/nsswitch.conf`
- configures PAM via marker-delimited edits: `pam_sss` in
  `/etc/pam.d/system-auth`, `pam_mkhomedir` and `pam_group` in
  `/etc/pam.d/system-login`, supplementary groups in `/etc/security/group.conf`
- configures the detected login manager (SDDM / GDM / LightDM) to allow login
  with domain usernames that aren't in the local user list
- optionally points the system's DNS at the UCS domain controller (`--force-ucs-dns`)
- backs up every file it touches before changing it, and restores them
  automatically if the join fails part-way

## Status

Early development. Tested against UCS 5 (with Samba AD) from an Arch Linux
container. Not yet published to the AUR; the PKGBUILDs under `packaging/`
build from a release tag.

## Usage

Install the dependencies:

```
sudo pacman -S python python-ldap python-dnspython python-netifaces \
  sshpass openssh sssd krb5 chrony ca-certificates-utils openldap
```

Join (from a checkout, run `PYTHONPATH=. python3 scripts/cli.py` instead of
`univention-arch-connector-cli`):

```
sudo univention-arch-connector-cli --username Administrator --password-file /path/to/pwfile
```

The UCS domain is detected from this host's DNS domain (or a parent domain
of it), reverse DNS, or the configured nameservers. If that fails, pass
`--domain example.com` or `--dc-ip <address>`.

Before connecting, the tool shows the domain controller's SSH host key
fingerprints and asks you to confirm them. Compare them with the output of
this command on the domain controller:

```
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

For unattended joins, pass the fingerprint instead:
`--dc-fingerprint SHA256:...`.

To undo a join (the computer object in UCS is left for you to remove in UMC):

```
sudo univention-arch-connector-cli --leave-domain
```

Run `univention-arch-connector-cli --help` for all options. The graphical
assistant `univention-arch-connector-gui` (started via the "Univention
Domain Join" desktop entry and polkit) offers the same options.

## Development

```
python -m pytest
```

runs the unit tests. CI runs them in an Arch Linux container on every push.
[tests/integration/MANUAL_UCS_CHECKLIST.md](tests/integration/MANUAL_UCS_CHECKLIST.md)
covers testing against a real UCS domain controller.

## License

AGPL-3.0-only. See [LICENSES/AGPL-3.0-only.txt](LICENSES/AGPL-3.0-only.txt) and [NOTICE.md](NOTICE.md).
