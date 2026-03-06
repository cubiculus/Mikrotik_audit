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
    "/interface bridge print detail",
    "/interface bridge port print",
    "/interface bridge vlan print detail",
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
    "/ip route print detail",
    '/ip route print detail where routing-mark!=""',
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
    
    # Firewall
    "/ip firewall filter print detail without-paging",
    "/ip firewall nat print detail without-paging",
    "/ip firewall mangle print detail without-paging",
    "/ip firewall raw print detail",
    # Firewall - Address Lists
    "/ip firewall address-list print detail",
    "/ip firewall layer7-protocol print detail",
    "/ip firewall connection tracking print",
    "/ip firewall connection print detail",
    "/ip firewall service-port print",
    
    # Services
    "/ip service print detail",
    "/ip ssh print",
    
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
    "/system certificate print detail",
    "/system backup print",
    
    # Users & Access
    "/user print detail",
    "/user group print detail",
    "/user ssh-keys print",
    
    # Disk & Files
    "/disk print detail",
    "/file print detail",
    
    # Interfaces - General
    "/interface print detail",
    "/interface print stats",
    "/interface bridge print detail",
    "/interface bridge port print",
    "/interface bridge vlan print",
    "/interface ethernet print detail",
    "/interface vlan print detail",
    "/interface veth print detail",
    
    # Interfaces - Wireless (RouterOS v6)
    "/interface wireless print detail",
    
    # Interfaces - WiFi (RouterOS v7)
    "/interface wifi print detail",
    "/interface wifi security print detail",
    "/interface wifi registration-table print detail",
    
    # Containers
    "/container print detail",
    "/container config print",
    "/container image print",
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
    "/ip address print where interface~\"veth\"",
    "/ip arp print detail",
    "/ip neighbor print detail",
    "/ip cloud print",
    
    # Routing
    "/ip route print detail",
    "/ip route export",
    '/ip route print detail where routing-mark!=""',
    "/ip route print detail where gateway~\"veth\"",
    "/routing rule print detail",
    "/ip route rule print detail",
    "/routing table print detail",
    "/routing table print",
    "/routing filter print detail",
    "/routing vrf print detail",
    
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
    "/ip dns print detail",
    "/ip dns cache print detail",
    "/ip dns static print detail",
    
    # DHCP & Pools
    "/ip pool print detail",
    "/ip dhcp-server print",
    "/ip dhcp-server network print detail",
    "/ip dhcp-server lease print detail",
    "/ip dhcp-server option print detail",
    "/ip dhcp-server option sets print",
    
    # Firewall - Filter
    "/ip firewall filter print detail without-paging",
    "/ip firewall filter print detail where action=drop",
    '/ip firewall filter print detail where protocol=udp',
    
    # Firewall - NAT
    "/ip firewall nat print detail without-paging",
    
    # Firewall - Mangle
    "/ip firewall mangle print detail without-paging",
    '/ip firewall mangle print detail where action~"mss"',
    
    # Firewall - Raw & Other
    "/ip firewall raw print detail",
    # Firewall - Address Lists
    "/ip firewall address-list print detail",
    "/ip firewall layer7-protocol print",
    "/ip firewall service-port print",
    "/ip firewall export verbose",
    
    # Firewall - Connections
    "/ip firewall connection tracking print",
    "/ip firewall connection print detail",
    "/ip firewall connection print count-only",
    
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
    "/ip ssh print",
    "/ip ssh print detail",
    
    # Queues (QoS)
    "/queue simple print detail",
    "/queue simple print stats",
    "/queue tree print detail",
    "/queue tree print stats",
    "/queue type print",
    
    # CAPsMAN / WiFi
    "/caps-man interface print detail",
    
    # Monitoring & Tools
    "/tool netwatch print detail",
    "/ip accounting snapshot print",
    # Sniffer использует интерфейс по умолчанию или первый доступный
    # Интерфейс определяется автоматически через /interface print
    "/tool sniffer quick protocol=tcp duration=30",

    # Logs
    '/log print where topics~"firewall"',
    '/log print where topics~"ovpn"',
    '/log print where topics~"wireguard"',
    "/log print follow=no count=500 without-paging",
    
    # Connectivity Tests
    "/ping 8.8.8.8 count=5",
    # Проверка доступности интернета через ping (вместо fetch к внешнему серверу)
    "/ping 1.1.1.1 count=3",
    
    # Export
    "/export hide-sensitive",
]