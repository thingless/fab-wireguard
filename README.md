These fab 1.X jobs set up a wireguard overlay network between multiple hosts.

Cool features:
1. ipv4 and ipv6 supported (both required right now)
2. all traffic between the wg IPs is encrypted & authenticated
3. traffic travels point-to-point between nodes with reachable endpoints
4. traffic stays within provider networks if "region" feature is used
5. road warriors can dial into the network from behind NAT, assuming they can reach all public endpoints
6. private keys never move - they are generated & stored in /etc/wireguard on each machine

Few issues to resolve:
1. support for non-Ubuntu hosts
2. better support for non-DO hosts in get_ip_addresses()
3. do not restart the wg interfaces on each reconfig (wg-quick strip)
4. wg_reconfig_all job that uses hosts.yaml to update all hosts
5. add support for generating PowerDNS config files for .srv. records

Caveats:
1. Unreachable nodes (i.e. road warriors) cannot talk to each other, only to publicly reachable nodes.

HOWTO:

Zeroth, get the dependencies. Tested in python2, but might work with 3 with minor changes:
```
pip2 install fabric<2.0 ipaddress pyyaml tornado
```

First, edit config/hosts.yaml and define a network.
```
networks:
- name: net0
  ip4: 10.60.0.0/24
  ip6: 2001:0DB8:1234:5678::/64  -- pick an fd00::/8 subnet from https://www.ultratools.com/tools/rangeGenerator
  psk: (result of `wg genpsk`, optional)
```


Second, run `wg_register_host` job on all new or changed hosts. This job assigns IPs & edits hosts.yaml, so no parallel! Arguments:
```
network='net0'
hostname=None    # None -> use the host's configured hostname
region=None      # if set, assume private IPs are reachable from all hosts in region
reachable=True   # set to false for road warriors behind a nat etc
```


Third, run `wg_reconfig` on _all_ hosts in the network. This job actually creates the wg config files. Arguments:
```
network='net0'
hostname=None       # None -> use the host's configured hostname
can_register=False  # if set to True, will try to register any unknown hosts - will need to run reconfig a second time
```


A few example commands from my testing:
```
fab -f wireguard.py --user root -H 128.199.8.213,128.199.8.53,143.110.148.29,143.110.155.200 wg_register_host
fab -P -f wireguard.py --user root -H 128.199.8.213,128.199.8.53,143.110.148.29,143.110.155.200 wg_reconfig
```
