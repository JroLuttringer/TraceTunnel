import sys
import os
from TraceTunnel import *

INIT_PORT = 1024
INIT_CODE = 0

TRIES = 10

UDP_dic = {}
TCP_dic = {}
ICMP_dic = {}

reached = 0
targets = ['193.51.177.17', '193.51.177.82', '193.51.177.11', "193.51.177.222", '193.51.177.196', '193.51.177.218', '193.51.180.13', '193.51.177.64','193.51.177.232']


def add_to_dic(entry, dic):
    global reached
    entry_str = ""
    for e in entry:
        if e is None:
            e = "*"
        entry_str += e + " -- "
    if entry[-1] is not None:
        reached += 1

    if entry_str in dic:
        dic[entry_str] += 1
    else:
        dic[entry_str] = 1

for target in targets:
    UDP_dic = {}
    TCP_dic = {}
    ICMP_dic = {}
    reached = 0
    for x in range(0, TRIES):
        route_udp = launch_TT_import(target, 'udp', INIT_PORT+x, None, print_trace=False)
        route_tcp = launch_TT_import(target, 'tcp', INIT_PORT+x, None, print_trace=False)
        route_icmp = launch_TT_import(target, 'icmp', None, INIT_CODE+x, print_trace=False)
        add_to_dic(route_udp, UDP_dic)
        add_to_dic(route_tcp, TCP_dic)
        add_to_dic(route_icmp, ICMP_dic)


    print("Target: %s" % target)
    print(" -target reached %s/30" % reached)
    print(" UDP:")
    print(UDP_dic)
    print("\n TCP:")
    print(TCP_dic)
    print("\n ICMP:")
    print(ICMP_dic)
    print(" -------------------------------------------------------------")
