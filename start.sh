#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run univention-arch-connector from a checkout, without installing the
# packages under packaging/. Installs missing dependencies (after asking),
# then starts the graphical assistant in a graphical session and the CLI
# otherwise.
#
#   ./start.sh                     GUI if a display is available, else CLI
#   ./start.sh --gui               graphical assistant
#   ./start.sh --cli [OPTIONS...]  command line; OPTIONS go to the CLI,
#                                  e.g. ./start.sh --cli --list-shares
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

base_packages=(python python-ldap python-dnspython python-netifaces sshpass openssh
               sssd krb5 chrony ca-certificates-utils openldap)
gui_packages=(python-pyqt5)
share_packages=(cifs-utils pam_mount keyutils)

die() { echo "start.sh: $*" >&2; exit 1; }

mode=auto
case "${1:-}" in
    --gui) mode=gui; shift ;;
    --cli) mode=cli; shift ;;
    -h|--help) sed -n '/^#   /s/^#//p' "$0"; exit 0 ;;
esac
if [[ $mode == auto ]]; then
    if [[ $# -gt 0 ]]; then
        mode=cli
    elif [[ -n ${WAYLAND_DISPLAY:-} || -n ${DISPLAY:-} ]]; then
        mode=gui
    else
        mode=cli
    fi
fi
[[ $mode == gui && $# -gt 0 ]] && die "--gui takes no further options"

[[ -r /etc/arch-release ]] || grep -qs '^ID\(_LIKE\)\?=.*arch' /etc/os-release \
    || die "this is not Arch Linux or an Arch-based distribution"

if [[ $EUID -ne 0 ]]; then
    # Keep the graphical session reachable for the GUI.
    session_env=(DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR XAUTHORITY)
    if command -v sudo >/dev/null; then
        exec sudo --preserve-env="$(IFS=,; echo "${session_env[*]}")" "$0" "--$mode" "$@"
    elif command -v run0 >/dev/null; then
        setenv=()
        for name in "${session_env[@]}"; do
            [[ -n ${!name:-} ]] && setenv+=("--setenv=$name")
        done
        exec run0 "${setenv[@]}" "$0" "--$mode" "$@"
    fi
    die "run this as root (neither sudo nor run0 is available)"
fi

wanted=("${base_packages[@]}")
[[ $mode == gui ]] && wanted+=("${gui_packages[@]}")
[[ $mode == gui || " $* " == *" --setup-shares "* || " $* " == *" --mount-home "* ]] && wanted+=("${share_packages[@]}")
mapfile -t missing < <(pacman -T "${wanted[@]}" || true)
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing packages: ${missing[*]}"
    if [[ -t 0 ]]; then
        read -rp "Install them now with pacman? [Y/n] " answer
        [[ ${answer,,} == n* ]] && die "cannot continue without: ${missing[*]}"
    else
        die "install them first: pacman -S --needed ${missing[*]}"
    fi
    pacman -S --needed --noconfirm "${missing[@]}"
fi

export PYTHONPATH="$repo${PYTHONPATH:+:$PYTHONPATH}"
# Running as root must not leave root-owned __pycache__ in a user's checkout.
export PYTHONDONTWRITEBYTECODE=1
if [[ $mode == gui ]]; then
    exec python3 "$repo/scripts/gui.py"
fi
exec python3 "$repo/scripts/cli.py" "$@"
