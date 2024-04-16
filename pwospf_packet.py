from scapy.fields import IntField, ByteField, ShortField, LenField, IPField, LongField, PacketListField, FieldLenField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.utils import checksum
import struct

HELLOINT = 5
DEFAULT_MASK = "255.255.255.0"
PWOSPF_PROTOCOL = 89
TTL = 64


class PWOSPF_Header(Packet):
    name = "PWOSPF_Header"
    fields_desc = [ ByteField("version", 2),
                    ByteField("type", 1),
                    LenField("len", None),
                    IPField("router_id","0.0.0.0"),
                    IPField("area_id","0.0.0.0"),
                    ShortField('checksum', None),
                    ShortField("Autype",0),
                    LongField("Authentication", 0)]
    def post_build(self, p, pay):
        if self.len is None:
            new_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", new_len) + p[4:]
        if self.checksum is None:
            # Checksum is calculated without authentication data
            # Algorithm is the same as in IP()
            ck = checksum(p[:16] + pay)
            p = p[:12] + struct.pack("!H", ck) + p[14:]
        return p + pay
    
    
class PWOSPF_Hello(Packet):
    name = "PWOSPF_Hello"
    fields_desc = [
        IPField("mask", DEFAULT_MASK),
        ShortField("helloint", HELLOINT),
        ShortField("padding",0)
    ]


class PWOSPF_LSA(Packet):
    name = "PWOSPF_LSA"
    fields_desc = [
        IPField("subnet", DEFAULT_MASK),
        IPField("mask", DEFAULT_MASK),
        IPField("router_id", DEFAULT_MASK)
    ]
    def extract_padding(self, p):
        return "", p
    
class PWOSPF_LSU(Packet):
    name = "PWOSPF_LSU"
    fields_desc = [
        ShortField("sequence", 0),
        ShortField("ttl",TTL),
        # IntField("num_advertisements",0),
        FieldLenField("num_advertisements",None, fmt="I", count_of="link_state_ads"),
        PacketListField("link_state_ads",[], PWOSPF_LSA, count_from=lambda pkt: pkt.num_advertisements)
        # PacketListField("link_state_ads", [], PWOSPF_LSA)
    ]



bind_layers(IP,PWOSPF_Header, proto=PWOSPF_PROTOCOL)
bind_layers(PWOSPF_Header,PWOSPF_Hello,type=1)
bind_layers(PWOSPF_Header,PWOSPF_LSU,type=4)
bind_layers(PWOSPF_LSU,PWOSPF_LSU)