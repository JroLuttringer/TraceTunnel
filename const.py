import socket
import sys
import struct



# Erreursc
UDP_TIMEOUT = "UDP timeout"
TCP_TIMEOUT = "TCP timeout"
PING_TIMEOUT = "PING Timeout"
ICMP_TIMEOUT = "ICMP Timeout"
PORT_ERROR = "Port unreachable"
UDP_ERROR = "UDP packet failed"
HOP_ERROR = "No answer"
DEST_UNREACHABLE_MSG = "Dest unreach"

# Trace constantes
PORT = 443
MAX_HOPS_FORWARD = 30 # Trace stops at 30 hops
MAX_TIMEOUT = 3 # Trace stops after 3 timeouts
TIMEOUT = 0.5 # seconds before timeout
K = 1
ZOO_TRACE_PORT = 20000
gns3_zoo_ip = "130.79.90.202"

# Indicator (mpls tunnels revelation)
NO_INDICATOR = 255
OPAQUE = 2
DUP_IP = 3
RTL = 4
FRPLA = 5
ERROR = -1
FRPLA_THRESHOLD = 3
RTLA_THRESHOLD = 3

# Types & IP packet constants
TIME_EXCEEDED = 11
PORT_UNREACHABLE = 3
DEST_UNREACHABLE = 3
ECHO_REPLY = 0
ECHO_REQUEST = 8
MPLS_THRESHOLD = 150
UDP_ID = "udp"
TCP_ID = "tcp"
ICMP_ID = "icmp"


gns3_addresses = ["192.168.3.1", "192.168.3.2", "192.168.5.1", "130.79.91.1","130.79.91.2", "130.79.90.105","130.79.90.106","130.79.90.2", "130.79.90.1",
"192.168.8.2","10.5.0.1","10.1.0.1", "10.1.0.2","10.6.0.1","10.2.0.1",
"10.2.0.2", "10.7.0.1", "10.3.0.1", "10.3.0.2", "10.8.0.1", "10.4.0.1", "10.4.0.2",
"10.11.0.1", "10.9.0.1", "10.11.0.2", "10.12.0.1", "10.9.0.1", "192.168.2.1",
"192.168.2.2", "192.168.6.1", "192.168.4.1", "192.168.4.2", "192.168.7.1", "130.79.91.105",
"200.168.8.1", "200.168.8.2" ]
gns3_addresses = []
