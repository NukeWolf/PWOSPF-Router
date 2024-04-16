from scapy.fields import BitField, ByteField, ShortField, LenField, IPField, LongField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.utils import checksum
import struct

HELLOINT = 5
DEFAULT_MASK = "255.255.255.0"
PWOSPF_PROTOCOL = 89


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
            new_len = 24 + len(pay)
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


bind_layers(PWOSPF_Header,PWOSPF_Hello,type=1)