# Manual end-to-end checklist against a real UCS domain controller

Unit tests cover the pure logic offline; everything that actually talks to
a UCS domain controller (LDAP object creation, Kerberos, SSSD against real
LDAP, login manager behavior at the greeter) needs a real lab setup.

## Setup

1. Provision a UCS 5.x VM as DC Master in an isolated lab network. Note its
   IP address, domain name, and LDAP base DN.
2. Provision a fresh Arch Linux or CachyOS VM on the same network, default
   install, with NetworkManager and systemd-resolved active.
3. Install this project (either via the PKGBUILDs under `packaging/`, or by
   running `scripts/cli.py` directly from a checkout with the venv's
   dependencies installed and `PYTHONPATH` set).

## Join

4. Run as root:
   ```
   univention-arch-connector-cli --dc-ip <ip> --username Administrator --password-file /path/to/pwfile
   ```
   - [ ] The DC's SSH host key fingerprints are shown and must be confirmed;
     answering "no" aborts before any credentials are sent.
   - [ ] Without a terminal, the join refuses to continue unless
     `--dc-fingerprint` is given; a wrong fingerprint is rejected.
   - [ ] Without `--dc-ip`, the domain is auto-detected, also when the
     client's DNS domain is a subdomain of the UCS domain.
   - [ ] Run through `sudo` (or `./start.sh` as a normal user), not as
     root: the join, a failing join's rollback and `--leave-domain` work.
   - [ ] On a client whose DNS server doesn't know the UCS domain (e.g. the
     router's), the join aborts and suggests `--force-ucs-dns`; with it,
     the join succeeds and SSSD is online (`sssctl domain-status`).
   - [ ] With the FQDN in `/etc/hostname`, the computer object is still
     named (and found) by the short hostname.
   - [ ] While the join runs, `/dev/shm/univention-arch-connector-*` on the
     DC is mode 600, and it's gone afterwards.
5. Verify:
   - [ ] The computer object appears in UCS UMC under `cn=computers`.
   - [ ] `/etc/sssd/sssd.conf`, `/etc/krb5.conf`, `/etc/openldap/ldap.conf`
     (`ldapsearch -x -ZZ` works without `-H`/`-b`),
     `/etc/machine.secret` (mode 600) were written.
   - [ ] `/etc/pam.d/system-login` and `/etc/security/group.conf` each
     contain exactly one `univention-arch-connector` marker block, and
     `/etc/pam.d/system-auth` contains one `pam_sss` block each for auth,
     account, password and session.
   - [ ] Re-running the join produces **no duplicate** marker blocks
     (idempotency).
   - [ ] `/etc/nsswitch.conf` has `sss` appended on the `passwd`, `group`,
     and `shadow` lines, with existing tokens (e.g. `[SUCCESS=merge]
     systemd`) intact.
   - [ ] The UCS root CA is present under
     `/etc/ca-certificates/trust-source/anchors/UCSdomain.crt`, identical to
     `/etc/univention/ssl/ucsCA/CAcert.pem` on the DC, and `trust list`
     shows it.
   - [ ] A join that fails part-way (e.g. stop the DC's Kerberos service
     mid-join) restores every changed file and stops SSSD.

## Login

6. Reboot. At the greeter (test SDDM, GDM, LightDM and Plasma Login separately, on
   separate VMs or by switching `display-manager.service`), log in as a UCS
   domain user that is **not** a local user. At Plasma Login, use "Type in
   Username and Password"; domain users aren't in its user list.
   - [ ] Login succeeds and a home directory is auto-created
     (`pam_mkhomedir`).
   - [ ] `id <user>` shows the supplementary groups
     (`audio,cdrom,dialout,floppy,plugdev,adm`).
   - [ ] `kinit <user>` and `klist -e` work, with AES (not RC4/DES) enctypes.
   - [ ] `getent passwd <user>` resolves via SSSD.

   - [ ] After `--login-user-list known`, the greeter lists the domain
     users who logged in on this computer before (and preselects the last
     one); a domain user logging in for the first time appears after
     logging out. `all` lists all active domain users (no `$` computer
     accounts, `krbtgt`, `Guest` or hidden service accounts); `hide` returns
     to local users only. A re-join keeps the setting.

## Options

7. On a second clean VM, test `--force-ucs-dns`, once with systemd-resolved
   and once with NetworkManager without systemd-resolved:
   - [ ] Nameservers point at the UCS DC afterward, also after a reboot.
   - [ ] `_domaincontroller_master._tcp.<domain>` SRV resolves.
   - [ ] `--leave-domain` removes the drop-in under
     `/etc/systemd/resolved.conf.d/` or `/etc/NetworkManager/conf.d/`.
8. Test `--skip-login-manager`:
   - [ ] No login-manager conflict check or config file is touched.
   - [ ] With an unknown login manager (e.g. plasma-login-manager), the join
     only warns, and domain users can log in at its greeter.
9. Test `--leave-domain`:
   - [ ] Marker blocks removed from `system-auth`/`system-login`/`group.conf`/`nsswitch.conf`.
   - [ ] `sssd.conf`, `krb5.conf`, `ldap.conf` restored to their pre-join
     state (or removed, if they didn't exist before).
   - [ ] The UCS CA trust anchor is removed.
   - [ ] Also after joining twice in a row: `--leave-domain` uses the
     backup from before the first join, so `sssd.conf` and the CA are
     removed rather than restored.
   - [ ] `/var/univention-arch-connector-backup` is mode 700, and backups
     older than the pre-join one were removed.
   - [ ] The domain user can no longer log in; local users are unaffected.
   - [ ] The computer object in UCS was **not** removed automatically (by
     design) - confirm the tool logged a reminder to do it manually.

## Network shares

Needs a VM or privileged container: unprivileged containers can't mount
CIFS. Install `cifs-utils pam_mount keyutils`, create a share in UMC and,
for one test user, a home share (`sambahome`) for step 12.

11. `--list-shares` lists the UCS shares; `--setup-shares <name>` sets one up.
    - [ ] Logging in as a domain user mounts it at `~/Freigaben/<name>`
      without asking for a password, using the user's ticket
      (`/tmp/krb5cc_<uid>`); `ls` shows the files, writing respects the
      user's permissions in UCS.
    - [ ] A local user's login mounts nothing and isn't slowed down.
    - [ ] Logging out unmounts the shares.
    - [ ] `--remove-shares` and `--leave-domain` remove the volumes from
      `/etc/security/pam_mount.conf.xml` and `pam_mount` from
      `/etc/pam.d/system-login`.
12. Join with `--mount-home`.
    - [ ] At login, `~/Freigaben/Home` holds the user's home from the server
      (`\\<samba/homedirserver>\<user>`), also when logging in as
      `user@domain`; a user with their own `sambahome` gets that one.
    - [ ] A re-join without the option keeps it; `--no-mount-home` and
      `--leave-domain` remove it.

## GUI

10. Launch via the desktop entry (`univention-arch-connector.desktop`).
    - [ ] A polkit (`pkexec`) prompt appears.
    - [ ] The wizard completes and produces the same result as the CLI.
    - [ ] On a joined system, a note at the top names the domain, DC and join
      date; username, domain, DC IP, fingerprint and options are prefilled
      from the last join (domain/DC/DNS only, for systems joined before
      this was recorded), and the button reads "Join again".
