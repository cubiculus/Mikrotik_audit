"""Audit command definitions for MikroTik routers."""

# Standard RouterOS audit commands
AUDIT_COMMANDS_BASIC = [
    "/system identity print",
    "/system package print",
    "/ip address print detail",
    "/interface print detail",
    "/system resource print",
    "/system clock print",
]

AUDIT_COMMANDS_STANDARD = [
    # System
    "/system identity print",
    "/system package print",
    "/system resource print",
    "/system clock print",
    "/system history print",
    "/system note print",
    "/system logging print detail",
    "/system health print",
    "/system routerboard print",
    "/system license print",
    "/user print detail",
    "/user group print detail",

    # Interfaces
    "/interface print detail",
    "/interface print stats",
    "/interface list print detail",
    "/interface list member print detail",
    # Bridge
    "/interface bridge print detail",
    "/interface bridge port print detail",
    "/interface bridge vlan print detail",
    "/interface bridge host print detail where local=no",
    # Ethernet/VLAN
    "/interface ethernet print detail",
    "/interface vlan print detail",
    "/interface veth print detail",

    # Containers
    "/container print detail",
    "/container config print",

    # WireGuard
    "/interface wireguard print detail",
    "/interface wireguard peers print detail",

    # IP & Routing
    "/ip address print detail",
    "/ip address print detail where disabled=no",
    "/ip route print detail",
    "/ip route print detail where active=yes",
    "/ip route print detail where active=no",
    '/ip route print detail where routing-mark!=""',
    # "/ip rule print detail",  # RouterOS v7: bad command name - use /ip route rule instead
    "/routing rule print detail",
    "/routing table print detail",
    "/ip arp print detail",
    "/ip neighbor print detail",

    # DNS
    "/ip dns print",
    "/ip dns static print detail",

    # DHCP
    "/ip pool print detail",
    "/ip dhcp-server print",
    "/ip dhcp-server network print detail",
    "/ip dhcp-server lease print detail",
    "/ip dhcp-server lease print detail where status=bound",
    "/ip dhcp-server lease print detail where address-lists!=\"\"",
    "/ip dhcp-server option print detail",  # Fixed: was /ip dhcp-option print detail

    # Firewall - Filter
    "/ip firewall filter print detail without-paging",
    "/ip firewall filter print chain=input",
    "/ip firewall filter print chain=forward",
    "/ip firewall filter print chain=output",
    # Firewall - NAT
    "/ip firewall nat print detail without-paging",
    # Firewall - Mangle
    "/ip firewall mangle print detail without-paging",
    "/ip firewall mangle print detail chain=prerouting where disabled=no",
    "/ip firewall mangle print detail chain=forward where disabled=no",
    "/ip firewall mangle print detail chain=postrouting where disabled=no",
    # Firewall - Raw
    "/ip firewall raw print detail",
    # Firewall - Address Lists
    "/ip firewall address-list print detail",
    "/ip firewall address-list print detail where dynamic=no",
    "/ip firewall address-list print detail where dynamic=yes",
    # Firewall - Connections
    "/ip firewall connection tracking print",
    "/ip firewall connection print detail",
    "/ip firewall connection print detail where connection-mark!=\"\"",
    "/ip firewall connection print detail where routing-mark!=\"\"",
    "/ip firewall connection print detail where connection-state=established",
    # Firewall - Service Ports
    "/ip firewall service-port print",
    "/ip firewall layer7-protocol print detail",

    # Services
    "/ip service print detail",
    "/ip ssh print",  # RouterOS v7 doesn't support 'detail' for this command

    # PPP/VPN
    "/ppp active print detail",
    "/ppp profile print detail",
    "/ppp secret print detail",
    "/interface pptp-server print",

    # IPsec
    "/ip ipsec peer print detail",
    "/ip ipsec policy print detail",
    "/ip ipsec policy print detail where active=yes",

    # Queues
    "/queue simple print detail",
    "/queue simple print stats",
    "/queue tree print detail",
    "/queue tree print stats",
    "/queue type print",

    # Logs - RouterOS v7 doesn't support count= parameter
    "/log print without-paging",  # Fixed: was /log print count=50
    '/log print where message~"firewall" without-paging',

    # Connectivity Tests
    "/ping 8.8.8.8 count=5",
    # Проверка доступности интернета через ping (вместо fetch к внешнему серверу)
    "/ping 1.1.1.1 count=3",

    # Export
    "/export hide-sensitive",
]

AUDIT_COMMANDS_COMPREHENSIVE = [
    # System Info
    "/system identity print",
    "/system resource print",
    "/system resource cpu print",
    "/system package print",
    "/system package update print",
    "/system clock print",
    "/system history print",
    "/system note print",
    "/system script print detail",
    "/system scheduler print detail",
    "/system logging print detail",
    "/system health print",
    "/system routerboard print",
    "/system license print",
    # "/system certificate print detail",  # RouterOS v7: bad command name
    "/certificate print detail",  # Fixed for RouterOS v7
    # "/system/backup/export",  # RouterOS v7: bad command name - already in /export

    # Users & Access
    "/user print detail",
    "/user group print detail",
    "/user ssh-keys print",

    # Disk & Files
    "/disk print",
    "/file print",

    # Interfaces - General
    "/interface print detail",
    "/interface print stats",
    "/interface list print detail",
    "/interface list member print detail",
    # Bridge
    "/interface bridge print detail",
    "/interface bridge port print detail",
    "/interface bridge vlan print",
    "/interface bridge host print detail where local=no",
    # Ethernet/VLAN
    "/interface ethernet print detail",
    "/interface vlan print detail",
    "/interface veth print detail",

    # Interfaces - Wireless (RouterOS v6) - not available in v7
    # "/interface wireless print detail",  # RouterOS v7: bad command name

    # Interfaces - WiFi (RouterOS v7)
    "/interface wifi print detail",
    "/interface wifi security print detail",
    "/interface wifi registration-table print detail",

    # Containers
    "/container print detail",
    "/container config print",
    # "/container image print",  # RouterOS v7: bad command name
    "/container envs print detail",
    "/container mounts print detail",

    # WireGuard VPN
    "/interface wireguard print detail",
    "/interface wireguard peers print detail",

    # VPN Clients (L2TP/SSTP/OVPN)
    "/interface ovpn-server print detail",
    "/interface l2tp-client print detail",
    "/interface sstp-client print detail",
    "/interface ovpn-client print detail",

    # IP Addressing
    "/ip address print detail",
    "/ip address print detail where disabled=no",
    "/ip address print where interface~\"veth\"",
    "/ip arp print detail",
    "/ip neighbor print detail",
    "/ip cloud print",

    # Routing
    "/ip route print detail",
    "/ip route print detail where active=yes",
    "/ip route print detail where active=no",
    "/ip route export",
    '/ip route print detail where routing-mark!=""',
    "/ip route print detail where gateway~\"veth\"",
    # "/ip rule print detail",  # RouterOS v7: bad command name
    "/routing rule print detail",
    # "/ip route rule print detail",  # RouterOS v7: bad command name - use /routing rule
    "/routing table print detail",
    "/routing table print",
    # "/routing filter print detail",  # RouterOS v7: bad command name
    # "/routing vrf print detail",  # RouterOS v7: bad command name

    # Routing Protocols - BGP
    "/routing bgp instance print detail",
    "/routing bgp connection print detail",

    # Routing Protocols - OSPF
    "/routing ospf instance print detail",
    "/routing ospf interface print detail",
    "/routing ospf neighbor print detail",

    # Routing Protocols - RIP
    "/routing rip interface print detail",
    "/routing rip neighbor print detail",

    # IPv6
    "/ipv6 address print detail",
    "/ipv6 route print detail",
    "/ipv6 firewall filter print detail",

    # DNS
    "/ip dns print",
    # "/ip dns print detail",  # RouterOS v7: expected end of command
    "/ip dns cache print detail",
    "/ip dns static print detail",

    # DHCP & Pools
    "/ip pool print detail",
    "/ip dhcp-server print",
    "/ip dhcp-server network print detail",
    "/ip dhcp-server lease print detail",
    "/ip dhcp-server lease print detail where status=bound",
    "/ip dhcp-server lease print detail where address-lists!=\"\"",
    "/ip dhcp-server option print detail",
    # "/ip dhcp-option print detail",  # RouterOS v7: bad command name - duplicate
    "/ip dhcp-server option sets print",

    # Firewall - Filter
    "/ip firewall filter print detail without-paging",
    "/ip firewall filter print chain=input",
    "/ip firewall filter print chain=forward",
    "/ip firewall filter print chain=output",
    "/ip firewall filter print chain=kid-control",
    "/ip firewall filter print detail where action=drop",
    '/ip firewall filter print detail where protocol=udp',

    # Firewall - NAT
    "/ip firewall nat print detail without-paging",

    # Firewall - Mangle
    "/ip firewall mangle print detail without-paging",
    "/ip firewall mangle print detail chain=prerouting where disabled=no",
    "/ip firewall mangle print detail chain=forward where disabled=no",
    "/ip firewall mangle print detail chain=postrouting where disabled=no",
    '/ip firewall mangle print detail where action~"mss"',

    # Firewall - Raw
    "/ip firewall raw print detail",

    # Firewall - Address Lists
    "/ip firewall address-list print detail",
    "/ip firewall address-list print detail where dynamic=no",
    "/ip firewall address-list print detail where dynamic=yes",
    "/ip firewall layer7-protocol print",
    "/ip firewall service-port print",
    "/ip firewall export verbose",

    # Firewall - Connections
    "/ip firewall connection tracking print",
    "/ip firewall connection print detail",
    "/ip firewall connection print count-only",
    "/ip firewall connection print detail where connection-mark!=\"\"",
    "/ip firewall connection print detail where routing-mark!=\"\"",
    "/ip firewall connection print detail where connection-state=established",

    # IPsec
    "/ip ipsec policy print detail",
    "/ip ipsec peer print detail",
    "/ip ipsec identity print detail",
    "/ip ipsec profile print detail",
    "/ip ipsec proposal print detail",
    "/ip ipsec active-peers print",
    "/ip ipsec installed-sa print",

    # PPP & VPN Services
    "/ppp active print detail",
    "/ppp secret print detail",
    "/ppp profile print detail",
    "/ip hotspot print",
    "/ip hotspot active print",
    "/ip hotspot user print",
    "/ip proxy print",
    "/ip proxy access print",

    # Services & SSH
    "/ip service print detail",
    "/ip ssh print",  # RouterOS v7 doesn't support 'detail' for this command

    # Queues (QoS)
    "/queue simple print detail",
    "/queue simple print stats",
    "/queue tree print detail",
    "/queue tree print stats",
    "/queue type print",

    # CAPsMAN / WiFi
    # "/caps-man interface print detail",  # RouterOS v7: bad command name

    # Monitoring & Tools
    "/tool netwatch print detail",
    # "/ip accounting snapshot print",  # RouterOS v7: bad command name
    # Sniffer использует интерфейс по умолчанию или первый доступный
    # Интерфейс определяется автоматически через /interface print
    # "/tool sniffer quick protocol=tcp duration=30",  # RouterOS v7: expected end of command

    # Logs - RouterOS v7 doesn't support count= parameter
    # "/log print without-paging",  # RouterOS v7: expected end of command
    '/log print where message~"firewall" without-paging',
    '/log print where message~"ovpn" without-paging',
    '/log print where message~"wireguard" without-paging',
    # "/log print follow=no without-paging",  # RouterOS v7: expected end of command

    # Connectivity Tests
    "/ping 8.8.8.8 count=5",
    # Проверка доступности интернета через ping (вместо fetch к внешнему серверу)
    "/ping 1.1.1.1 count=3",

    # Export
    "/export hide-sensitive",
]
