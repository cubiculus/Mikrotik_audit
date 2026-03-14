"""Fixtures with ANONYMIZED RouterOS v7 output for testing.

All sensitive data has been replaced with placeholder values.
DO NOT use real router data in tests.
"""

# Real interface print stats output from RouterOS v7.22 (ANONYMIZED)
INTERFACE_STATS_OUTPUT = """Flags: X - DISABLED; R - RUNNING; S - SLAVE

Columns: NAME, RX-BYTE, TX-BYTE, RX-PACKET

 #     NAME                         RX-BYTE        TX-BYTE  RX-PACKET

 0  R  ether1                 2 360 330 144    572 441 255  3 205 419

 1 X S ether2                             0              0          0

 2 X S ether3                             0              0          0

 3   S ether4                             0              0          0

 4  RS ether5                             0      1 302 728          0

;;; VETH for Container 1

 5  RS CONTAINER1-TUN          36 552 256     47 124 055    389 838

;;; Bridge for Container 1

 6  R  CONTAINER1-BR            31 094 092     46 656 533    389 832

;;; VETH for Container 2

 7  RS CONTAINER2-TUN               1 426        469 421         19

;;; Bridge for Container 2

 8  R  CONTAINER2-BR                  804            440         14

;;; Bridge for Container 3

 9  R  CONTAINER3-BR                  728            440         13

;;; VETH for Container 3

10  RS CONTAINER3-TUN               1 426        469 474         19

;;; VETH for Container 4

11  RS CONTAINER4-TUN             194 422        873 342      1 153

;;; Bridge for Container 4

12  R  CONTAINER4-BR             177 896        404 275      1 147

13  R  bridge1                  514 372 886  2 261 294 259    958 232

14  R  internal                      65 548         15 302        540

15  R  lo                             2 788          2 788         29

16  R  pppoe-out1             2 256 621 560    539 196 847  2 671 063

17  RS veth-app                      73 108         14 862        540

18 X   wg-site2site                       0              0          0

19   S wifi1                     86 529 734    779 359 748    183 878

20  RS wifi2                    403 809 383    874 707 724    568 365

21   S wifi3                              0              0          0

22  RS wifi4                     36 340 733    609 559 890    204 311
"""

# Real interface print detail output from RouterOS v7.22 (ANONYMIZED)
INTERFACE_DETAIL_OUTPUT = """Flags: X - DISABLED; R - RUNNING; S - SLAVE

 0  R  ;;; ether1 - WAN
      name="ether1" type="ether" mtu=1500 l2mtu=2028 mac-address=00:00:00:00:00:01
      running=yes disabled=no

 1 X S ;;; ether2 - LAN (slave)
      name="ether2" type="ether" mtu=1500 l2mtu=2028 mac-address=00:00:00:00:00:02
      running=yes disabled=yes

 5  RS ;;; VETH for Container 1
      name="CONTAINER1-TUN" type="veth" mtu=1500 mac-address=00:00:00:00:00:05
      running=yes disabled=no rx-byte=36552256 tx-byte=47124055

 6  R  ;;; Bridge for Container 1
      name="CONTAINER1-BR" type="bridge" mtu=1500 mac-address=00:00:00:00:00:06
      running=yes disabled=no rx-byte=31094092 tx-byte=46656533
"""

# Real firewall filter output from RouterOS v7.22 (ANONYMIZED)
FIREWALL_FILTER_OUTPUT = """Flags: X - DISABLED, I - INVALID; D - DYNAMIC

 0  D ;;; special dummy rule to show fasttrack counters

      chain=forward action=passthrough



 1    ;;; 1. FastTrack (MUST BE FIRST! for performance)

      chain=forward action=fasttrack-connection routing-mark=!to-vpn_route

      log=no log-prefix=""



 2    ;;; jump to kid-control rules

      chain=forward action=jump jump-target=kid-control



 3    ;;; 3. Allow established/related/untracked (reduce CPU load)

      chain=forward action=accept

      connection-state=established,related,untracked



 4    ;;; Allow DNS responses from Container

      chain=input action=accept protocol=udp src-address=192.168.2.3

      dst-port=53
"""

# Real firewall NAT output from RouterOS v7.22 (ANONYMIZED)
FIREWALL_NAT_OUTPUT = """Flags: X - DISABLED, I - INVALID; D - DYNAMIC

 0    ;;; Masquerade LAN

      chain=srcnat action=masquerade out-interface=pppoe-out1



 1    ;;; Custom DNS for 192.168.1.145

      chain=dstnat action=dst-nat to-addresses=1.1.1.1 protocol=udp

      src-address-list=vpn-only-clients dst-port=53 log=no log-prefix=""



 2    ;;; Custom DNS for 192.168.1.145 TCP

      chain=dstnat action=dst-nat to-addresses=1.1.1.1 protocol=tcp

      src-address-list=vpn-only-clients dst-port=53 log=no log-prefix=""
"""

# Real IP address output from RouterOS v7.22 (ANONYMIZED)
IP_ADDRESS_OUTPUT = """Flags: X - DISABLED, I - INVALID; D - DYNAMIC; S - SLAVE

 0     address=192.168.1.1/24 network=192.168.1.0 interface=bridge1

       actual-interface=bridge1 vrf=main



 1     ;;; Gateway for Container 1 network

       address=192.168.3.2/24 network=192.168.3.0 interface=CONTAINER1-BR

       actual-interface=CONTAINER1-BR vrf=main



 2     ;;; Gateway for Container 2 network

       address=192.168.2.1/24 network=192.168.2.0 interface=CONTAINER2-BR

       actual-interface=CONTAINER2-BR vrf=main



 3     ;;; Gateway for Container 3 network

       address=192.168.4.1/24 network=192.168.4.0 interface=CONTAINER3-BR

       actual-interface=CONTAINER3-BR vrf=main
"""

# Real system resource output from RouterOS v7.22 (ANONYMIZED)
SYSTEM_RESOURCE_OUTPUT = """
                   uptime: 4h56m22s

                  version: 7.22 (stable)

               build-time: 2026-03-09 08:38:02

         factory-software: 7.5

              free-memory: 429.4MiB

             total-memory: 1024.0MiB

                      cpu: ARM64

                cpu-count: 4

            cpu-frequency: 1320MHz

                 cpu-load: 3%

           free-hdd-space: 68.7MiB

          total-hdd-space: 128.0MiB

  write-sect-since-reboot: 927

         write-sect-total: 491328

               bad-blocks: 0%

        architecture-name: arm64

               board-name: hAP ax^3

                 platform: MikroTik
"""

# Real veth detail output from RouterOS v7.22 (ANONYMIZED)
VETH_DETAIL_OUTPUT = """Flags: X - DISABLED; R - RUNNING

 0  R ;;; VETH for Container 1

      name="CONTAINER1-TUN" mac-address=00:00:00:00:00:05

      container-mac-address=00:00:00:00:00:06 address=192.168.3.1/24

      gateway=192.168.3.2 gateway6="" dhcp=no dhcp-address=""



 1  R ;;; VETH for Container 2

      name="CONTAINER2-TUN" mac-address=00:00:00:00:00:07

      container-mac-address=00:00:00:00:00:08 address="" gateway=""

      gateway6="" dhcp=no dhcp-address=""



 2  R ;;; VETH for Container 3

      name="CONTAINER3-TUN" mac-address=00:00:00:00:00:09

      container-mac-address=00:00:00:00:00:0A address=192.168.4.3/24

      gateway=192.168.4.1 gateway6="" dhcp=no dhcp-address=""
"""

# Real WireGuard peers output from RouterOS v7.22 (ANONYMIZED)
WIREGUARD_PEERS_OUTPUT = """Flags: X - DISABLED; D - DYNAMIC

 0    interface=wg-site2site name="peer2"

      public-key="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX="

      endpoint-address=example.sn.mynetname.net endpoint-port=13231

      current-endpoint-address="" current-endpoint-port=0

      allowed-address=10.99.99.2/32 persistent-keepalive=25s

      client-endpoint="" client-allowed-address=::/0 rx=0 tx=0
"""

# Real history output from RouterOS v7.22 (ANONYMIZED)
HISTORY_OUTPUT = """Flags: U - UNDOABLE

Columns: ACTION, BY, POLICY, TIME

  ACTION                   BY         POLICY  TIME

U user user2 changed       user1      write   2026-03-14 21:48:37

                                      policy
"""

# Real log output from RouterOS v7.22 (ANONYMIZED)
LOG_OUTPUT = """Flags: X - DISABLED, I - INVALID; * - DEFAULT

 0  * topics=info prefix="" regex="" action=memory



 1  * topics=error prefix="" regex="" action=memory



 2  * topics=warning prefix="" regex="" action=memory



 3  * topics=critical prefix="" regex="" action=echo



 4    topics=container,debug prefix="" regex="" action=memory
"""

# Real health output from RouterOS v7.22 (ANONYMIZED)
HEALTH_OUTPUT = """Columns: NAME, VALUE, TYPE

#  NAME             VALUE  TYPE

0  cpu-temperature     58  C
"""
