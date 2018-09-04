import copy
import pypacket
from const import *
import logging

'''
class mpls_data_struct
contains info regarding the mpls protocol found in the quoted IP message
(label and ttl value)
'''
class mpls_mini_struct():
    def __init__(self, label, ttl):
        self.label = label
        self.ttl = ttl

class mpls_data_struct():
    def __init__(self, label, ttl):
        self.mpls_info = []
        self.mpls_info.append(mpls_mini_struct(label, ttl))

    def add_infos(self,label, ttl):
        self.mpls_info.append(mpls_mini_struct(label, ttl))


'''
class hops
contains infos regarding one hop found during the trace
'''
class hop():
    def __init__(self, name=None, addr=None, ttl_I=None, ttl_R=None, q_ttl=None, err=None):
        self.name = name # dns name
        self.addr = addr # ip addr
        self.ttl_init = ttl_I # ttl at which the node was found
        self.ttl_reply = ttl_R # ttl of the reply message
        self.q_ttl = q_ttl # quoted ttl
        self.err = err # error message
        self.frpla_value = 0 # value of the triggers (added later)
        self.rtl_value = 0
        self.frpla_diff = 0 # difference between the current trigger value and the previous hop
        self.rtl_diff = 0
        self.qttl_diff = 0

'''
class hop2
contains 2 hop() instances: one containing the probe info, one containing the ping info
one boolean indication if the hop had to be revealed by using the buddy method,
and an mpls_data_struct class containing eventual mpls informations
'''
class hop2():

    def __init__(self, info=None, ping_info=None, mpls_info=None):
        self.info = info
        self.buddy_used = False
        self.ping_info = ping_info
        self.mpls_info = mpls_info

    # return a copy of the hop2 structure with a different ip
    def change_ip(self, new_ip):
        newhop = copy.deepcopy(self)
        newhop.info.addr = new_ip
        return newhop

    # to print hop2 instances
    def to_str(self, invisible=False):
        if self.info.err == HOP_ERROR:
            return "%3s  *  [%s]" % (self.info.ttl_init, self.info.err)

        error = None
        mpls = None
        if(invisible):
            rev = "[REVEALED]"
        else:
            rev = ""

        ttl = self.info.ttl_init
        name = self.info.name
        addr = self.info.addr
        if (self.ping_info.err is not None):
            ping_ttl = "*"
            error = "[" + self.ping_info.err + "]"
        else:
            ping_ttl = self.ping_info.ttl_reply
        signature = "<%s,%s>" % (self.info.ttl_reply, ping_ttl)
        q_ttl = self.info.q_ttl

        # basic info + frpla value
        hop_str = "%3s %s %s (%11s)  %s [ frpla = %s ]" % (
            ttl, rev, name, addr, signature, self.info.frpla_value
        )

        # add rtla value if signature is 255, 64
        if ping_ttl != "*" and ping_ttl < 128 and self.info.ttl_reply > 128:
            hop_str = hop_str + "[ rtla = %s(%s) ]" % (self.info.rtl_value ,self.info.rtl_diff)

        # add uturn and qttl indicators
        hop_str = hop_str + "[ qttl = %s ][ uturn = %s ]" % ( q_ttl,self.info.rtl_value )

        # add meta info
        meta_indicators = "[ meta = %s, %s, %s ] " % (self.info.frpla_diff, self.info.qttl_diff, self.info.rtl_diff)
        hop_str = hop_str + meta_indicators

        # add mpls info and error
        if(self.mpls_info is not None and len(self.mpls_info.mpls_info) != 0):
            mpls = " [MPLS LSE |"
            for x in self.mpls_info.mpls_info:
                mpls += " Label : %s | mTTL : %s #" % (
                    x.label, x.ttl)
            # remove last ''#''
            mpls = mpls[:-1]
        if mpls is not None:
            hop_str = hop_str + "%s] " % (mpls)

        if error != None :
            hop_str = hop_str + "%s " % (error)


        return hop_str
