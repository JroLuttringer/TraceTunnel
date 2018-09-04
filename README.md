# TraceTunnel

TraceTunnel is a traceroute-like tool, which displays the path/route between the
vantage point and the target. In addition, TraceTunnel looks for evidence of MPLS tunnels
at each hop that it reveals. If an indicator/trigger is detected, TraceTunnel tries to reveal
the MPLS tunnel, and displays the results.
By default, TraceTunnel uses UDP probe. If left unanswered, an ICMP probe is then used.

## Prerequisites
* Python 3 and up
* Scapy

```
sudo apt-get install python3
pip3 install scapy
```

## Installing

Once the Prerequisites are installed, clone the git repo

```
git clone https://git.unistra.fr/jrluttringer/TraceTunnel.git
```

##  Usage
Run TraceTunnel
```
sudo python3 TraceTunnel.py 8.8.8.8
```
Note: TraceTunnel can be imported as a module and used by calling
 **launch_TT_import**(target, protocol, port, code)
protocol, port or code can be set as None. Returns the list of ips seen/revealed along the path. **Still under developpment**

### Options
* **--proto udp**: Only use UDP probes
* **--proto tcp**: Only use TCP SYN probes
* **--proto icmp**: Only use ICMP Echo Requests probes
* **--port x**: Use port x as the destination port
* **--no-reveal**: Do not attempt any MPLS tunnel revelation
* **--code**: ICMP code to use when sending Echo-Request messages
* **--zoo**: Visit our MPLS tunnel zoo (See below) **(Not working yet)**

### Examples
Hidden MPLS tunnel revelation.
Hops marked as REVEALED would be invisible to the standard traceroute implementation.
```
$ sudo python3 TraceTunnel.py 192.168.7.1
Launching TraceTunnel: 192.168.7.1 (192.168.7.1)

  1  192.168.3.2 (192.168.3.2)  <255,255> [ frpla = 0 ][ qttl = 1 ][ uturn = 0 ][ meta = 0, 0, 0 ]
  2  192.168.8.2 (192.168.8.2)  <254,254> [ frpla = 0 ][ qttl = 1 ][ uturn = 0 ][ meta = 0, 0, 0 ]

    FRPLA | Length estimation : 3 | Revealed : 3 (difference : 0)
     2.1 [REVEALED] 10.1.0.2 (   10.1.0.2)  <253,253> [ frpla = 0 ][ qttl = None ][ uturn = 0 ][ meta = 0, 0, 0 ] - step 2
     2.2 [REVEALED] 10.2.0.2 (   10.2.0.2)  <252,252> [ frpla = 0 ][ qttl = None ][ uturn = 0 ][ meta = 0, 0, 0 ] - step 1
     2.3 [REVEALED] 10.3.0.2 (   10.3.0.2)  <251,251> [ frpla = 0 ][ qttl = None ][ uturn = 0 ][ meta = 0, 0, 0 ] - step 0

  3  10.4.0.2 (   10.4.0.2)  <250,250> [ frpla = 3 ][ qttl = 1 ][ uturn = 0 ][ meta = 3, 0, 0 ]
  4  CE2 (192.168.2.2)  <250,250> [ frpla = 2 ][ qttl = 1 ][ uturn = 0 ][ meta = -1, 0, 0 ]
  5  192.168.7.1 (192.168.7.1)  <250,250> [ frpla = 1 ][ qttl = None ][ uturn = 0 ][ meta = -1, 1, 0 ]
  ```
  Explicit VPN
  ```
    1  192.168.3.2 (192.168.3.2)  <255,255> [ frpla = 0 ][ qttl = 1 ][ uturn = 0 ][ meta = 0, 0, 0 ]
    2  10.0.0.54 (  10.0.0.54)  <254,254> [ frpla = 0 ][ qttl = 1 ][ uturn = 0 ][ meta = 0, 0, 0 ]
    3  10.0.0.14 (  10.0.0.14)  <245,255> [ frpla = 8 ][ qttl = 1 ][ uturn = 0 ][ meta = 8, 0, 0 ][MPLS LSE | Label : 23 | mTTL : 1 # Label : 28 | mTTL : 1 ]
    4  10.0.0.22 (  10.0.0.22)  <246,*> [ frpla = 6 ][ qttl = 2 ][ uturn = 0 ][ meta = -2, -1, 0 ][MPLS LSE | Label : 17 | mTTL : 1 # Label : 28 | mTTL : 2 ] [PING Timeout]
    5  10.0.0.222 ( 10.0.0.222)  <247,255> [ frpla = 4 ][ qttl = 3 ][ uturn = 0 ][ meta = -2, -1, 0 ][MPLS LSE | Label : 17 | mTTL : 1 # Label : 28 | mTTL : 3 ]
    6  10.0.0.58 (  10.0.0.58)  <250,250> [ frpla = 0 ][ qttl = 3 ][ uturn = 0 ][ meta = -4, 0, 0 ]
    7  10.0.1.103 ( 10.0.1.103)  <249,249> [ frpla = 0 ][ qttl = None ][ uturn = 0 ][ meta = 0, 3, 0 ]
  ```
  The trace is displayed following this format:
  #hop DNS_NAME   IP <TE_TTL, PING_TTL> [FRPLA] [RTLA] [QTTL] [UTURN] [META] [MPLS] [ERROR]

* **TE_TTL**: The Time-to-Live of the Time-Exceeded reply triggered by the probe
* **PING_TTL**: The TTL of the Echo-Reply message
* **FRPLA**: Value of the FRPLA trigger. Used to detect MPLS tunnels.
* **RTLA**: Value of the RTLA trigger. Used to detect MPLS tunnels.
* **QTTL**: TTL of the probe when the Time-Exceeded reply was sent. Retrieved in the quotation of the IP packet that triggered the Time-Exceeded reply
* **UTURN**: Value of the UTURN indicator. Used to detect MPLS tunnels.
* **META**: Describes the evolution of the three triggers/indicators between two hops.
* **MPLS**: MPLS header quoted in the Time-Exceeded reply. See RFC 4950 (https://tools.ietf.org/html/rfc4950)
* **ERROR**: Errors encountered (Ping timeout, UDP timeout, and so on)

## Files
* **const.py** : contains the constant variables used by TraceTunnel
* **pyhop.py**: contains the pyhop structure used to store hop informations
* **pypacket.py**: contains functions used to send probes and retrieve useful informations
* **TraceTunnel.py**: contains revelation/detection implementations

## Created with
* [Scapy](https://github.com/secdev/scapy)

## Detailed explanations
See [TraceTunnel: Discovering Hidden MPLS Tunnels](https://drive.google.com/open?id=1p_23qiWnqE4gU4-KS-obQZJI07LjNyQ4)
