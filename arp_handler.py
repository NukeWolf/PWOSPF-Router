from scapy.all import Packet, Ether, IP, ARP, ls
from cpu_metadata import CPUMetadata

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

class ArpHandler():
    def __init__(self,sw,mac,ip):
        self.table = dict()
        self.packet_buffer = dict()
        self.mac = mac
        self.ip = ip
        self.sw = sw
        
    
    def is_ip_in_arp_table(self, ip):
        return ip in self.table
    
    def find_mac(self,pkt):
        ip = pkt[IP].dst
        arp_req_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) / CPUMetadata() / ARP(hwlen=6, plen=4, op=ARP_OP_REQ, hwsrc=self.mac,
            psrc=self.ip, hwdst='00:00:00:00:00:00', pdst=ip)
        if ip not in self.packet_buffer:
            self.packet_buffer[ip] = []
        self.packet_buffer[ip].append(pkt)
        
        return arp_req_pkt
    
    def update_entry(self,ip,mac):
        # TODO: Check for existing entries? Don't make copies or override.
        if ip not in self.table:
            self.table[ip] = mac
            self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'meta.next_hop_ip': [ip]},
                action_name='MyIngress.set_ether',
                action_params={'dst': mac})
        
        if ip in self.packet_buffer:
            held_packets = self.packet_buffer[ip]
            del self.packet_buffer[ip]
            return held_packets
        else:
            return []
        
        
    # def get_arp_entry(self, ip):
        
        


