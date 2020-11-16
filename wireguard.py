from __future__ import absolute_import
from __future__ import print_function

import StringIO
import contextlib
import functools
import os
import re
import textwrap
import sys
import json
import hashlib

from fabric.api import hide, run, env, sudo, put, get, cd, settings, hosts, local, lcd, execute
import fabric.contrib.files
from fabric.context_managers import shell_env

try:  # py3
    from shlex import quote as shell_quote
except ImportError:  # py2
    from pipes import quote as shell_quote

# Path to config files
CFG_DIR = 'config'

class HostsDB(object):
    def __init__(self, path=os.path.join(CFG_DIR, 'hosts.yaml')):
        self.path = path
        self.data = None

    def load(self, force=False):
        if not force and self.data is not None:
            return self.data  # already loaded
        import yaml
        with open(self.path) as inp:
            self.data = yaml.full_load(inp)
        if not self.data:
            self.data = {}
        if not self.data.get('hosts'):
            self.data['hosts'] = []  # for new users
        if not self.data.get('networks'):
            self.data['networks'] = []  # doomed, but at least an error will throw
        return self.data

    def save(self):
        if self.data is None:
            return  # no save without load first
        import yaml
        with open(self.path, 'w') as out:
            yaml.dump(self.data, out)

    def find_host_by_name(self, hostname):
        db = self.load()
        for host in db['hosts']:
            if host['name'] == hostname:
                return host

    def find_net_by_name(self, netname):
        db = self.load()
        for network in db['networks']:
            if network['name'] == netname:
                return network

    def find_free_ip_address(self, network):
        import ipaddress

        db = self.load()
        net = self.find_net_by_name(network)
        if not net:
            return

        used_ip4 = set()
        used_ip6 = set()
        for host in db['hosts']:
            used_ip4.add(ipaddress.ip_address(host['ip4'].decode()))
            used_ip6.add(ipaddress.ip_address(host['ip6'].decode()))

        ip4net = ipaddress.ip_network(net['ip4'].decode())
        ip6net = ipaddress.ip_network(net['ip6'].decode())

        ip4 = ip6 = None
        for ip in ip4net.hosts():
            if ip not in used_ip4:
                ip4 = ip
                break

        for ip in ip6net.hosts():
            if ip not in used_ip6:
                ip6 = ip
                break

        return ip4 and str(ip4), ip6 and str(ip6)

    def upsert_host(self, host):
        db = self.load(force=True)
        oldhost = self.find_host_by_name(host['name'])
        if oldhost:
            oldhost.update(host)
        else:
            db['hosts'].append(host)
        self.save()

    def all_hosts(self):
        db = self.load()
        return db['hosts']

def get_ip_addresses():
    """Return the public & private IP addresses of this server.

    Will throw if there's no public IP or more than one private IP.

    XXX: somewhat hacky nonsense, mostly tailored for Digital Ocean

    Returns:
      (pub_ip, priv_ip) -> string IP or None if missing
    """

    try:
        # Get the remote IP addresses
        ip_txt = run("ip addr | grep 'inet\ ' | grep -vF 127.0.0.1 | awk '{print $2}'", warn_only=True)
        ips = [x.split('/')[0] for x in ip_txt.split('\n')]

        # Split into public and private IPs
        priv_ips = [ip for ip in ips if ip.startswith('10.')]
        priv_ips += [ip for ip in ips if ip.startswith('192.168.')]
        priv_ips += [ip for ip in ips if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-2])\.', ip)]
        pub_ips = [ip for ip in ips if ip not in priv_ips]
        priv_ips = [ip for ip in priv_ips if not re.match(r'^172\.17\.', ip)]  # exclude docker IPs

        # The second private IP is the actual, routable one
        # It looks like this:
        # eth0:
        #    192.0.2.123    # public, external routable address
        #    10.17.0.22     # internal, non-routable address - seems to be for DO internal use only
        # eth1:
        #    10.210.14.222  # private, internal, routable address - can reach other DO droplets
        if len(priv_ips) == 2:
            priv_ips = [priv_ips[1]]

        # We should have one public IP and at most one private IP
        if len(pub_ips) != 1:
            raise Exception("Couldn't find a public IP (or too many)!")
        if len(priv_ips) > 1:
            raise Exception("More than one private IP!")

        return pub_ips[0], priv_ips[0] if priv_ips else None
    except Exception:
        ips = run("curl -s https://icanhazip.com").strip()
        return ips, None

def install_wireguard():
    if not run('wg version', warn_only=True).succeeded:
        # TODO: non-apt support
        sudo('apt-get update')
        sudo('DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confold" -y install wireguard')

def wg_genkey(network='net0', force=False):
    install_wireguard()
    privpath = '/etc/wireguard/{}.priv'.format(network)
    if force or not fabric.contrib.files.exists(privpath, use_sudo=True):
        sudo('wg genkey > ' + privpath)
        # ok this is dumb, but if there's a / in the privkey, regenerate it :/
        # then we can blindly use it in sed commands later
        while sudo('grep / ' + privpath + ' >/dev/null 2>/dev/null', warn_only=True).succeeded:
            sudo('wg genkey > ' + privpath)
    sudo('chown root.root ' + privpath)
    sudo('chmod 400 ' + privpath)
    pubkey = sudo('wg pubkey < ' + privpath)
    return pubkey.strip()

def wg_register_host(network='net0', hostname=None, region=None, reachable=True):
    db = HostsDB()
    if not db.find_net_by_name(network):
        raise ValueError("You must define the network first in hosts.yaml")

    if hostname is None:
        hostname = run('hostname').strip()

    host = db.find_host_by_name(hostname)
    if not host:
        # new host
        ip4, ip6 = db.find_free_ip_address(network)
        host = {
            'name': hostname,
            'net': network,
            'ip4': ip4,
            'ip6': ip6,
        }
        if reachable:
            host['port'] = 51820

    pub_ip, region_ip = get_ip_addresses()  # TODO might get wrong IP for region, more cloud support
    host['publicip'] = pub_ip
    if region and region_ip:
        host['regionip'] = region_ip
        host['region'] = region

    pubkey = wg_genkey(network=network)
    host['pubkey'] = pubkey

    db.upsert_host(host)
    return host

def wg_reconfig(network='net0', hostname=None, can_register=False):
    if hostname is None:
        hostname = run('hostname').strip()

    db = HostsDB()
    host = db.find_host_by_name(hostname)
    if not host and can_register:
        wg_register_host(network=network, hostname=hostname)  # call register host first
        db.load(force=True)
        host = db.find_host_by_name(hostname)
    if not host:
        raise ValueError("Cannot find host!?")
    net = db.find_net_by_name(host['net'])

    assert wg_genkey(network=network) == host['pubkey']

    peers = [h for h in db.all_hosts() if h['name'] != host['name'] and h['net'] == host['net']]
    for peer in peers:
        # same region?
        if peer.get('port') and peer.get('region') and peer['region'] == host.get('region') and peer.get('regionip'):
            peer['endpoint'] = peer['region_ip'] + ':' + str(peer['port'])
        elif peer.get('port') and peer.get('publicip'):
            peer['endpoint'] = peer['publicip'] + ':' + str(peer['port'])

    from tornado import template
    with open(os.path.join(CFG_DIR, 'wg-quick.conf.templ')) as inp:
        templ = template.Template(inp.read())
    txt = templ.generate(
        ip4mask=net['ip4'].split('/')[-1],
        ip6mask=net['ip6'].split('/')[-1],
        net=net,
        host=host,
        peers=[h for h in db.all_hosts() if h['name'] != host['name']],
    )

    privfile = '/etc/wireguard/{}.priv'.format(network)
    conffile = '/etc/wireguard/wg-{}.conf'.format(network)
    put(StringIO.StringIO(txt), conffile, use_sudo=True)
    sudo('chown root.root ' + conffile)
    sudo('chmod 0600 ' + conffile)

    # replace the private key
    sudo('''sed -i "s/##REPLACE WITH PRIVATE KEY##/$(cat {})/" {}'''.format(privfile,conffile))

    # reload the config
    # TODO: no interruptions
    sudo('wg-quick down wg-{0} ; wg-quick up wg-{0}'.format(network))
    sudo('systemctl enable wg-quick@wg-{}'.format(network))
