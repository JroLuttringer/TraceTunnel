#!/usr/bin/python

import sys  # to display results
import pypacket  # to create / read packets
import pyhop
import socket # for dns requests
from const import *
import time
import argparse


# variables globales
PRINT = True
REVEAL = True
revealed_ip_stack = []
ips_seen = []
PROTO = None
CODE = None

def myprint(str, ending = "\n", flush=True):
    if True or PRINT:
        print(str, end=ending, flush=flush)

"""
revealed ip class:
hop : hop2 instance, information of the revealed ip
itr: iteration of the revelation at which the hop was revealed
buddy_bit: indicates if the buddy was used to reveal the ip
"""
class revealed_ip():
    def __init__(self, hop, itr, buddy_bit):
        self.hop = hop
        self.itr = itr
        self.buddy_bit = buddy_bit


"""
Used during the revelation to check if the IP was already revealed
"""
def ip_in_stack(ip):
    i = 0
    while (i < len(revealed_ip_stack)):
        if (revealed_ip_stack[i].hop.info.addr == ip):
            return i + 1
        i = i + 1
    return 0


"""
Check if any of the hop contains stars (unanswered probes)
"""
def star_in(ni, ni1, ni2):
    ni_error = ni.info.err is not None
    ni1_error = ni1.info.err is not None
    ni2_error = ni2.info.err is not None
    return ni_error or ni1_error or ni2_error

"""
Check if an explicit mpls tunnnel was seen
"""
def explicit_mpls(ni, ni1, ni2):
    ni_mpls = ni.mpls_info is not None
    ni1_mpls = ni1.mpls_info is not None
    ni2_mpls = ni2.mpls_info is not None
    if not ni_mpls and  ni1_mpls and not ni2_mpls:
        return False
    return ni_mpls or ni1_mpls or ni2_mpls

"""
add elt to list if not already in the list
"""
def add_to_list_if_new(elt, list):
    if elt not in list or elt is None:
        list.append(elt)


# permet de trouver l'adresse se trouvant au "ttl-ieme" sauf sur le trajet
# entre l'envoyeur et la cible
# Envoie un paquet UDP et un paquet ICMP
#( afin d'obtenir la signature du routeur)
#
# Renvoie les informations contenu dans les header des paquets recu
"""
Send a probe with a specific ttl
sends one probe if the protocol was specified,
else sends an UDP probe. If the probe is left unanswered, sends an ICMP probe
"""
def tracehop(ttl, target_ip):
    if PROTO is None:
        hop_info, mpls_info = pypacket.get_time_exceeded_via_UDP(target_ip, ttl)
        #ICMP Trace if UDP trace failed
        if (hop_info.err is not None and hop_info.err is not PORT_ERROR):

            hop_info, mpls_info = pypacket.get_time_exceeded_via_ICMP(target_ip, ECHO_REQUEST, ttl)

    if PROTO == UDP_ID:
        hop_info, mpls_info = pypacket.get_time_exceeded_via_UDP(target_ip, ttl, PORT)
    if PROTO == ICMP_ID:
        hop_info, mpls_info = pypacket.get_time_exceeded_via_ICMP(target_ip, ECHO_REQUEST, ttl, CODE)
    if PROTO == TCP_ID:
        hop_info, mpls_info = pypacket.get_time_exceeded_via_TCP(target_ip, ttl, PORT)

    if (hop_info.err is not None and hop_info.err is not PORT_ERROR):
        hop_info = pyhop.hop(ttl_I = ttl, err=HOP_ERROR)
        return pyhop.hop2(info=hop_info)
    else:
        ping_info = pypacket.ping(hop_info.addr)

    return pyhop.hop2(hop_info, ping_info, mpls_info)


"""
Display te stack of revealed ips
"""

def trigger_to_string(indicator):
    if (indicator == DUP_IP):
        trig_disp = "    Duplicate IP "
        if (len(revealed_ip_stack) != 0):
            trig_disp = trig_disp + "(Egress : %s)" % revealed_ip_stack[0].hop.info.addr
    elif (indicator == RTL):
        trig_disp = "    RTL"
    elif (indicator == FRPLA):
        trig_disp = "    FRPLA"
    elif indicator == OPAQUE:
        trig_disp = "    OPAQUE"
    return trig_disp


def display_stack(c_ingress, c_egress, indicator):
    global revealed_ip_stack, ips_seen
    if(indicator == NO_INDICATOR):
        myprint("%s" % c_ingress.to_str(False))
        if c_ingress.info.addr not in ips_seen or c_ingress.info.addr is None:
            ips_seen.append(c_ingress.info.addr)
        return
    myprint("%s \n" % c_ingress.to_str())
    # Trigger to string
    trig_disp = trigger_to_string(indicator)

    #re-compute tunnel length estimation to display info
    length_estimation = (ttl_estimation(c_egress) - c_egress.info.ttl_init - K)
    revealed_hops = len(revealed_ip_stack)
    #compute diff between estimated length & real length
    difference = abs(
        (ttl_estimation(c_egress) - revealed_hops - c_egress.info.ttl_init - K))
    myprint(
        "%s | Length estimation : %s | Revealed : %s (difference : %s)" %
        (trig_disp, length_estimation, revealed_hops, difference))

    if (len(revealed_ip_stack) != 0):
        i = 1
        while(len(revealed_ip_stack) > 0):
            top = revealed_ip_stack.pop()
            top.hop.info.ttl_init = "%s.%s" % (c_ingress.info.ttl_init, i)
            if(top.buddy_bit):
                mode = " ( Buddy used ) "
            else:
                mode = ""
            myprint("     %s - step %s %s" % (
                top.hop.to_str(True), top.itr, mode)
            )
            i = i + 1

    else:
        if REVEAL:
            myprint("    No hidden hops were found\n")
        else:
            myprint("    Revelation not attempted\n")
    myprint("\n")
    revealed_ip_stack =[]

def compute_rtl(hop):
    rtl_value =0
    ttl_TE = hop.info.ttl_reply
    if ttl_TE > 128:
        if hop.ping_info.err is None :
            ttl_ER = hop.ping_info.ttl_reply
            if ttl_ER > 64:
                return 0
            else:
                comp_ER = 64
            rtl_value = (255 - ttl_TE) - (comp_ER - ttl_ER)
    return rtl_value

def compute_frpla(hop):
    frpla_value = 0
    ttl_TE = hop.info.ttl_reply
    max_value = 255
    if 0 <= ttl_TE <= 32:
        max_value = 32
    elif 32 <= ttl_TE <= 64:
        max_value = 64
    elif 64 <= ttl_TE <= 128:
        max_value = 128
    else:
        max_value = 255
    frpla_value = (max_value - ttl_TE) - (hop.info.ttl_init -1)
    return frpla_value

def check_indicators(ni2, ni1, ni):
    rtl_value = 0
    frpla_value = 0
    indicator_value = NO_INDICATOR

    if (star_in(ni2, ni1, ni)):
        return NO_INDICATOR, rtl_value, frpla_value

    # check opaque
    if(ni1.mpls_info is not None and len(ni1.mpls_info.mpls_info) == 1 and ni1.mpls_info.mpls_info[0].ttl > 230 and ni1.mpls_info.mpls_info[0].ttl < 255):
        indicator_value = OPAQUE

    # check ip dupliquee
    if(ni.info.addr == ni1.info.addr and ni.info.err is None):
        indicator_value = DUP_IP

    # RTL
    expected_length = compute_rtl(ni1)
    if (expected_length >= RTLA_THRESHOLD):
        indicator_value = min(indicator_value, RTL)
        rtl_value = expected_length

    # check FRPLA
    diff = compute_frpla(ni1)
    frpla_value = diff
    if(diff >= FRPLA_THRESHOLD):
        indicator_value = min(indicator_value, FRPLA)

    if explicit_mpls(ni2,ni1, ni):
        indicator_value = NO_INDICATOR


    ni.info.frpla_value = compute_frpla(ni)
    ni.info.rtl_value = compute_rtl(ni)

    ni1.info.frpla_value = frpla_value
    ni1.info.rtl_value = rtl_value

    ni.info.frpla_diff = ni.info.frpla_value - ni1.info.frpla_value
    ni.info.rtl_diff = ni.info.rtl_value - ni1.info.rtl_value
    ni_qttl = int(0 if ni.info.q_ttl is None else ni.info.q_ttl)
    ni1_qttl = int(0 if ni1.info.q_ttl is None else ni1.info.q_ttl)
    ni.info.qttl_diff = ni1_qttl - ni_qttl
    return indicator_value, rtl_value, frpla_value

'''
ttl_estimation
returns an estimation of the tunnel length to correctly set the ttl of the
tunnel revelation probe
'''
def ttl_estimation(egress):
    ttl = egress.info.ttl_init
    if (egress.ping_info.ttl_reply != None and egress.ping_info.ttl_reply < 128 and egress.info.ttl_reply > 128):
        ttl_TE = egress.info.ttl_reply
        ttl_ER = egress.ping_info.ttl_reply
        expected_length = (255 - ttl_TE) - (64 - ttl_ER)
        if (expected_length > 0):
            return ttl + expected_length + K

    if(egress.info.ttl_reply > 128):
        max_ttl = 255
    else:
        max_ttl = 64
    expected_length = (max_ttl - egress.info.ttl_reply) - (ttl -1)
    expected_length = max(expected_length, 0)
    ttl = ttl + expected_length + K
    return ttl


'''
Tunnel_Revelation
Reveal a potential mpls tunnel between egress and ingress
'''
def Tunnel_Revelation(egress, ingress):
    if not REVEAL:
        return
    global revealed_ip_stack
    revealed_ip_stack = []
    buddy_bit = False
    finished = False
    target = egress
    itr = 0
    pre_buddy_addr = None
    estimation = ttl_estimation(egress)

    # ttl estimation says that no tunnel is present
    if(estimation == ERROR):
        return
    myprint("\t Attempting to reveal a potential tunnel. Please wait  ", ending = "")
    while(not finished):
        estimation = ttl_estimation(target)
        if(estimation == ERROR):
            estimation = target.info.ttl_init
        # reveal as much as possible
        top_hop = Trace_push( target, itr, buddy_bit,  ingress,  estimation)
        if(top_hop.info.addr is None):
            finished = True
        else:
            if (top_hop.info.addr == target.info.addr) or top_hop.info.addr == pre_buddy_addr:
                if(buddy_bit):
                    finished = True
                    if top_hop.info.addr == pre_buddy_addr:
                        revealed_ip_stack = revealed_ip_stack[:-1]
                else:
                    pre_buddy_addr = top_hop.info.addr
                    target = top_hop.change_ip(buddy(top_hop.info.addr))
                    buddy_bit = True
            else:
                target = top_hop
                buddy_bit = False
        itr = itr + 1
        myprint("#", ending = "")
    myprint("\r", ending="")

'''
Trace_push
Used when revealing MPLS tunnels
Probes "backwards" from target to ingress, until ingress is touched or
an ip that was already seen is touched
'''
def Trace_push(target, itr, buddy_bit, ingress, ttl):
    global revealed_ip_stack
    i = ttl
    ingress_touched = False
    while not ingress_touched and i >= ingress.info.ttl_init - 1:
        hop = tracehop(i, target.info.addr)
        indice = ip_in_stack(hop.info.addr)
        if (hop.info.addr == ingress.info.addr):
            ingress_touched = True
            break
        if (hop.info.addr in ips_seen):
            break

        elif (not indice and (hop.info.addr != target.info.addr)):
            revealed_ip_elt = revealed_ip(hop, itr, buddy_bit)
            revealed_ip_stack.append(revealed_ip_elt)
        if(indice):
            revealed_ip_stack[indice-1].hop = hop
        i = i - 1

    if not ingress_touched or not len(revealed_ip_stack):
        if not ingress_touched and len(revealed_ip_stack) > 0:
            while(len(revealed_ip_stack) > 0 and revealed_ip_stack[len(revealed_ip_stack) - 1].itr == itr):
                revealed_ip_stack.pop()
        return target

    return revealed_ip_stack[-1].hop


'''
Buddy
Attempts to find the buddy of an ip (/30 or /31 network)
Used when revealed an UHP MPLS tunnel w/ Cisco 15.2 IOS
'''
def buddy(target_ip):
    last_number = int(target_ip.split('.')[-1])
    mod = last_number % 4
    buddy_ip = None
    network_number = last_number
    while (network_number % 4 != 0):
        network_number = network_number - 1
    network_addr = '.'.join(target_ip.split(
        '.')[:-1]) + str('.' + str(network_number))
    if (mod == 1 or mod == 2):
        ping = pypacket.ping(target_ip)
        if (ping.addr != network_addr):
            if(mod == 1):
                buddy_ip = '.'.join(target_ip.split('.')[:-1]) + str(
                    '.' + str(last_number + 1))
            else:
                buddy_ip = '.'.join(target_ip.split('.')[:-1]) + str(
                    '.' + str(last_number - 1))
            return buddy_ip

    if (mod == 0 or mod == 2):
        buddy_ip = '.'.join(target_ip.split('.')[:-1]) + str(
            '.' + str(last_number + 1))
    else:
        buddy_ip = '.'.join(target_ip.split('.')[:-1]) + str(
            '.' + str(last_number - 1))

    return buddy_ip




'''
TraceTunnel
Display the route between the host and the target
Check for mpls tunnel along the path, and attempt to reveal said tunnel if detected
Only one tunnel can be revealed along the path by default. The trace stop at 30 hops,
if a triple entry is seen, or when receiving a PORT UNREACHABLE ICMP message
'''
def TraceTunnel(target_name):
    myprint("\n")
    try:
        target_ip = socket.gethostbyname(target_name)
    except:
        myprint("Could not find host {0}\n".format(target_name))
        return
    myprint(
        "\nLaunching TraceTunnel: {0} ({1})\n\n".format(target_name,
                                                        target_ip)
    )

    # Initialize two first hops
    ni2 = tracehop(1, target_ip)
    ni1 = tracehop(2, target_ip)
    add_to_list_if_new(ni2.info.addr, ips_seen)
    add_to_list_if_new(ni1.info.addr, ips_seen)

    success = False
    target_reached = False
    ttl = 3

    while not target_reached and ttl < MAX_HOPS_FORWARD:
        ni = tracehop(ttl, target_ip)
        # check mpls tunnel presence indicator
        indicator, _, _ = check_indicators(ni2, ni1, ni)

        #do not attempt to reveal if a tunnel was already revealed (or if an attempt was made)
        if success:
            indicator = NO_INDICATOR
        if not success and indicator != NO_INDICATOR:
            if (indicator == DUP_IP and ni1.info.addr == ni2.info.addr):
                myprint("Triple address: trace stopped")
                break
            Tunnel_Revelation(ni1, ni2)
            success = True

        # display stack and check if target reached
        display_stack(ni2, ni1, indicator)
        if(ni.info.addr == target_ip or ni.info.err == PORT_UNREACHABLE):
            target_reached = True
        ttl = ttl + 1
        ni2 = ni1
        ni1 = ni

    if(len(revealed_ip_stack) == 0):
        myprint("%s" % ni2.to_str())
        add_to_list_if_new(ni2.info.addr, ips_seen)

    if(ni2.info.addr != ni1.info.addr):
        myprint("%s" % ni1.to_str())
        add_to_list_if_new(ni1.info.addr, ips_seen)

    # end of trace
    if (ttl >= MAX_HOPS_FORWARD):
        myprint("Trace stopped - Maximum hops reached")
    myprint("\n")


def launch_TT_import(target, proto, port, code, print_trace = True):
    #reset ips_seen global var
    global ips_seen
    ips_seen = []

    # change global variable according to arguments
    global PROTO
    global PORT
    global CODE
    global PRINT

    PROTO = proto
    PORT = port
    code = CODE
    PRINT = print_trace

    # launch tracetunnel & return list of revealed ips
    TraceTunnel(target)
    return(ips_seen)


def launch_TT():
    global PROTO
    global PORT
    global CODE
    global PRINT
    global REVEAL

    # parser arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type = str)
    parser.add_argument("--proto", type = str)
    parser.add_argument("--port", type = int)
    parser.add_argument("--code", type = int)
    parser.add_argument("--zoo", action = "store_true")
    parser.add_argument("--no-reveal", action="store_true")
    parser.add_argument("--no-print", action = "store_true")
    args = parser.parse_args()
    target_ip = None
    if args.zoo:
        target_ip = "130.79.91.106q"
    else:
        target_ip = args.target
    if args.target is None:
        myprint("No target ip specified")
        return
    if args.no_print :
        PRINT = False
    if args.no_reveal:
        REVEAL = False

    PROTO = args.proto
    if args.port != None:
        PORT = args.port
    CODE = args.code

    # launch TraceTunnel
    TraceTunnel(target_ip)



if __name__ == "__main__":
    launch_TT()
