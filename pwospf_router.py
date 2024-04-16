from threading import Thread, Event
import time

from pwospf_packet import PWOSPF_Header,PWOSPF_Hello
from cpu_metadata import CPUMetadata

from scapy.all import Packet, Ether, IP, ARP, ls


ALLSPFRouters_addr = "224.0.0.5"
PWOSPF_PROTOCOL = 89



class PWOSPF_Router(Thread):
    def __init__(self,mac,ip,send,mask):
        super(PWOSPF_Router, self).__init__()
        self.helloint = 10
        self.mac = mac
        self.ip = ip
        self.send_function = send
        self.mask = mask
        
    
    def run(self):
        while True:
            time.sleep(self.helloint)
            self.send_hello()
    def send_hello(self):
            hello_packet = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") / CPUMetadata(multicast=1) / IP(src=self.ip, dst=ALLSPFRouters_addr, proto=PWOSPF_PROTOCOL) / \
                PWOSPF_Header(router_id=self.ip, area_id=(self.ip)) / PWOSPF_Hello(mask=self.mask, helloint=self.helloint)
            
            self.send_function(hello_packet)

    def start(self, *args, **kwargs):
        super(PWOSPF_Router, self).start(*args, **kwargs)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PWOSPF_Router, self).join(*args, **kwargs)
        
    
    