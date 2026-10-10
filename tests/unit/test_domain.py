# SPDX-FileCopyrightText: 2026 univention-arch-connector contributors
# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path

from univention_arch_connector.utils import domain as d

RESOLVECTL_OUTPUT = """\
Global
           Protocols: +LLMNR +mDNS -DNSOverTLS DNSSEC=no/unsupported
         DNS Servers: 10.1.0.1 fd00::53%eth0
                      192.168.1.1#dns.lan
Fallback DNS Servers: 9.9.9.9#dns.quad9.net 2620:fe::9#dns.quad9.net
                      2606:4700:4700::1111#cloudflare-dns.com 8.8.8.8

Link 2 (eth0)
    Current Scopes: DNS
       DNS Servers: 10.0.0.1
     Default Route: yes
"""


def test_find_ucs_domain_walks_up_to_parent_domain(monkeypatch):
    monkeypatch.setattr(d, 'has_ucs_master_srv_record', lambda domain: domain == 'example.com')
    assert d.find_ucs_domain('site.example.com') == 'example.com'
    assert d.find_ucs_domain('a.b.site.example.com') == 'example.com'


def test_find_ucs_domain_prefers_the_most_specific_domain(monkeypatch):
    monkeypatch.setattr(d, 'has_ucs_master_srv_record', lambda domain: domain in ('site.example.com', 'example.com'))
    assert d.find_ucs_domain('site.example.com') == 'site.example.com'


def test_find_ucs_domain_never_tries_the_bare_tld(monkeypatch):
    tried = []
    monkeypatch.setattr(d, 'has_ucs_master_srv_record', lambda domain: tried.append(domain) or False)
    assert d.find_ucs_domain('site.example.com') == ''
    assert tried == ['site.example.com', 'example.com']


def test_domain_from_fqdn_without_domain_part(monkeypatch):
    monkeypatch.setattr(d, 'has_ucs_master_srv_record', lambda domain: True)
    assert d.get_ucs_domainname_from_fqdn('localhost') == ''


def test_parse_resolvectl_skips_fallback_servers_and_strips_suffixes():
    assert d.parse_resolvectl_nameservers(RESOLVECTL_OUTPUT) == {'10.1.0.1', 'fd00::53', '192.168.1.1', '10.0.0.1'}


def test_nameservers_from_resolv_conf(monkeypatch, tmp_path: Path):
    resolv_conf = tmp_path / 'resolv.conf'
    resolv_conf.write_text('# comment\nsearch example.com\nnameserver 10.1.0.1\nnameserver fd00::53\nnameserver bogus\n')
    monkeypatch.setattr(d, 'RESOLV_CONF', resolv_conf)
    assert d.get_nameservers_from_resolv_conf() == {'10.1.0.1', 'fd00::53'}


def test_nameservers_fall_back_to_resolv_conf_without_resolvectl(monkeypatch, tmp_path: Path):
    resolv_conf = tmp_path / 'resolv.conf'
    resolv_conf.write_text('nameserver 10.1.0.1\n')

    def no_resolvectl(*args, **kwargs):
        raise FileNotFoundError('resolvectl')

    monkeypatch.setattr(d.subprocess, 'check_output', no_resolvectl)
    monkeypatch.setattr(d, 'RESOLV_CONF', resolv_conf)
    assert d.get_nameservers() == {'10.1.0.1'}
