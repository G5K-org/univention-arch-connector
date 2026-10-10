# univention-arch-connector

Join Arch Linux (and Arch-based distributions: CachyOS, EndeavourOS, Manjaro, ...)
clients into a [Univention Corporate Server (UCS)](https://www.univention.com/)
domain, with the same feature set that Ubuntu/Linux Mint clients get from
Univention's official [`univention-domain-join`](https://github.com/univention/univention-domain-join).

This is an **unofficial, community port** — see [NOTICE.md](NOTICE.md) for
attribution and licensing. Not affiliated with Univention GmbH.

## What it does

When you join a client to the domain, the tool:

- creates an LDAP computer object for this machine on the UCS domain controller
- downloads and trusts the UCS root CA certificate
- writes `/etc/ldap/ldap.conf` and a machine account secret
- configures Kerberos (`/etc/krb5.conf`)
- configures SSSD for identity lookup (LDAP) and authentication (Kerberos)
- adds `sss` to `/etc/nsswitch.conf`
- configures PAM (`pam_mkhomedir`, supplementary group grants) via marker-delimited
  edits to `/etc/pam.d/system-login` and `/etc/security/group.conf`
- configures the detected login manager (SDDM / GDM / LightDM) to allow login
  with domain usernames that aren't in the local user list
- optionally points the system's DNS at the UCS domain controller (`--force-ucs-dns`)
- backs up every file it touches before changing it

## Status

Early development — see the plan/implementation order in this repository's
history. Not yet packaged for AUR.

## Usage

```
sudo univention-arch-connector-cli --username Administrator --password-file /path/to/pwfile
```

Run `univention-arch-connector-cli --help` for all options. A graphical
assistant (`univention-arch-connector`) is planned, mirroring upstream's GUI.

## License

AGPL-3.0-only. See [LICENSES/AGPL-3.0-only.txt](LICENSES/AGPL-3.0-only.txt) and [NOTICE.md](NOTICE.md).
