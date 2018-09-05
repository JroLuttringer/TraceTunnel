# Header : 0-20 IP  / 20:28 ICMP

# IPV4
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|Version|  IHL  |Type of Service|          Total Length         |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|         Identification        |Flags|      Fragment Offset    |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|  Time to Live |    Protocol   |         Header Checksum       |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                       Source Address                          |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                    Destination Address                        |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                    Options                    |    Padding    |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# ICMP
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|     Type      |     Code      |          Checksum             |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                             unused                            |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|      Internet Header + 64 bits of Original Data Datagram      |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
from scapy.all import *

# struct.data :
# b/B : 1 byte
# h/H : 2 bytes
# i/I : 4 bytes
# ! : Big endian / network order

import sys
import time  # Pour la creation du paquet icmp
import socket  # pour l'envoi des paquets UDP / ICMP
import struct  # Pour la lecture / la creation des paquets
import pyhop
import binascii
from const import *

'''
get mpls info from packet
'''
def extract_mpls(bytes):
    mpls_infos = None
    if len(bytes) < MPLS_THRESHOLD:
        return None
    else:
        bytes = bytes[-30:]
        i = 0
        for b in bytes:
            if bytes[i] == 0 and bytes[i+1] >= 8 and bytes[i+2] == 1 and bytes[i+3] == 1:
                number_of_headers = int((bytes[i+1] - 4) / 4)
                for x in range(0, number_of_headers):
                    bytes_mpls = bytes[i+x*4+4: i+ x*4 + 8]
                    names = ["label-ttl"]
                    struct_format = "!L"
                    unpacked_data = struct.unpack(struct_format, bytes_mpls)
                    d = dict(list(zip(names, unpacked_data)))
                    d["label"] = d["label-ttl"] >> 12
                    d["ttl"] = d["label-ttl"] & 255
                    if mpls_infos is None:
                        mpls_infos = pyhop.mpls_data_struct(d["label"],d["ttl"])
                    else:
                        mpls_infos.add_infos(d["label"], d["ttl"])

            i+=1
    return mpls_infos

def get_dns_name(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except socket.error:
        name = ip
    return name

def get_time_exceeded_via_UDP(target_ip, ttl_init, destport = PORT):
    save_target = target_ip
    # if targeting zoo
    if target_ip in gns3_addresses:
        destport = ZOO_TRACE_PORT
        data = "TNT:"+target_ip+":"
        target_ip = gns3_zoo_ip
        pkt = IP(dst=target_ip, ttl=ttl_init)/UDP(dport = destport, sport =destport)/Raw(load=data)
    else:
        pkt = IP(dst=target_ip, ttl=ttl_init)/UDP(dport = destport)


    reply, unans = sr(pkt, verbose=0, timeout=TIMEOUT)
    if len(reply) == 0 or reply[-1][1] is None:
        UDProbe_reply_info = pyhop.hop(ttl_I = ttl_init, err = UDP_TIMEOUT)
        return UDProbe_reply_info, None

    reply = reply[-1][1]
    err_msg = None
    if reply.haslayer(ICMP):
        qttl = reply.getlayer(ICMP).ttl
        if reply.getlayer(ICMP).type == DEST_UNREACHABLE:
            if reply.getlayer(ICMP).code == PORT_UNREACHABLE:
                err_msg = PORT_ERROR
            else:
                err_msg = "UDP " + DEST_UNREACHABLE_MSG
    else:
        qttl = -1

    UDProbe_reply_info = pyhop.hop(
        get_dns_name(reply.src),
        reply.src,
        ttl_init,
        reply.ttl,
        qttl,
        err = err_msg
    )
    mpls_info = extract_mpls(bytes(reply))
    return UDProbe_reply_info, mpls_info




def get_time_exceeded_via_TCP(target_ip, ttl_init, destport = PORT):
    save_target = target_ip
    if target_ip in gns3_addresses:
        destport = ZOO_TRACE_PORT
        data = "TNT:"+target_ip+":"
        target_ip = gns3gns3_zoo_ip
        pkt = IP(dst=target_ip, ttl=ttl_init)/TCP(dport = destport, sport =destport)/Raw(load=data)

    else:
        pkt = IP(dst=target_ip, ttl=ttl_init)/TCP(dport = destport)

    reply, unans = sr(pkt, verbose=0, timeout=TIMEOUT)
    if len(reply) == 0 or reply[-1][1] is None:
        TCProbe_reply_info = pyhop.hop(ttl_I = ttl_init, err = TCP_TIMEOUT)
        return TCProbe_reply_info, None

    reply = reply[-1][1]
    err_msg = None
    if reply.haslayer(ICMP):
        qttl = reply.getlayer(ICMP).ttl
        if reply.getlayer(ICMP).type == DEST_UNREACHABLE:
            if reply.getlayer(ICMP).code == PORT_UNREACHABLE:
                err_msg = PORT_ERROR
            else:
                err_msg = "TCP "+DEST_UNREACHABLE_MSG
    else:
        qttl = -1

    TCProbe_reply_info = pyhop.hop(
        get_dns_name(reply.src),
        reply.src,
        ttl_init,
        reply.ttl,
        qttl,
        err = err_msg
    )
    mpls_info = extract_mpls(bytes(reply))
    return TCProbe_reply_info, mpls_info


def get_time_exceeded_via_ICMP(target_ip, icmp_type_number, ttl, code = None):

    if target_ip in gns3_addresses:
        data = "TNT:"+target_ip+":"
        target_ip = gns3_zoo_ip
        pkt = IP(dst=target_ip, ttl =ttl)/ICMP()/Raw(load=data)
    elif code == None:
        pkt = IP(dst=target_ip, ttl =ttl)/ICMP()
    else:
        pkt = IP(dst=target_ip, ttl =ttl)/ICMP(code=code)

    reply = sr1(pkt, verbose=0, timeout=TIMEOUT)
    message = None
    if reply is None:
        if ttl == 255:
            message = PING_TIMEOUT
        else:
            message = ICMP_TIMEOUT
        ICMProbe_info = pyhop.hop(ttl_I=ttl, err=message)
        return ICMProbe_info, None

    type_icmp = reply.getlayer(ICMP).type
    if(type_icmp != ECHO_REPLY):
        qttl = reply.getlayer(ICMP).ttl
    else:
        qttl = None

    if type_icmp == DEST_UNREACHABLE:
        if reply.getlayer(ICMP).code == PORT_UNREACHABLE:
            message = PORT_ERROR
        else:
            if ttl != 255:
                message = "ICMP " + DEST_UNREACHABLE_MSG
            else:
                message = "PING " + DEST_UNREACHABLE_MSG

    ICMProbe_info = pyhop.hop(
        get_dns_name(reply.src), reply.src, ttl, reply.ttl, qttl, message)


    mpls_info = extract_mpls(bytes(reply))
    return ICMProbe_info, mpls_info


def ping(target_ip):
    return get_time_exceeded_via_ICMP(target_ip, ECHO_REQUEST, ttl=255)[0]
