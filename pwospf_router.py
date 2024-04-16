from threading import Thread, Event
import time
import ipaddress

from pwospf_packet import PWOSPF_Header,PWOSPF_Hello, PWOSPF_LSU, PWOSPF_LSA
from cpu_metadata import CPUMetadata

from scapy.all import Packet, Ether, IP, ARP, ls


ALLSPFRouters_addr = "224.0.0.5"
PWOSPF_PROTOCOL = 89

PWOSPF_HELLO_TYPE = 1
PWOSPF_LSU_TYPE = 4

LSUINT = 30
HELLOINT = 10

class PWOSPF_Interface():
    def __init__(self):
        self.NEIGHBOR_TIMEOUT_TIMER = 0
        self.neighbors = []
    def update_neighbors(self,ip,id,mac):
        found = False
        for x in self.neighbors:
            if x['router_mac'] == mac:
                found = True
        if not found:
            self.neighbors.append({
                'router_ip' : ip,
                'router_id' : id,
                'router_mac' : mac
            })
        self.NEIGHBOR_TIMEOUT_TIMER = 3
    def get_neighbors(self):
        return self.neighbors
    

class PWOSPF_LSU_Data():
    def __init__(self,ip,id):
        self.LSU_TIMEOUT_timer = 0
        self.current_sequence = -1
        self.router_id = 0
        self.router_ip = 0
        
        self.links = []
        

        

class PWOSPF_Router(Thread):
    def __init__(self,mac,ip,send,mask,area, num_ports):
        super(PWOSPF_Router, self).__init__()
        self.helloint = HELLOINT
        self.mac = mac
        self.ip = ip
        self.send_function = send
        self.mask = mask
        self.area = area
        
        self.interfaces = dict()
        for x in range(2,num_ports + 2):
            self.interfaces[x] = PWOSPF_Interface()
            
        
            
        #LSU Info
        self.sequence = 0
        self.LSUS = dict()
        
    
    def run(self):
        while True:
            time.sleep(self.helloint)
            self.send_hello()
    def send_hello(self):
            hello_packet = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") / CPUMetadata(multicast=1) / IP(src=self.ip, dst=ALLSPFRouters_addr, proto=PWOSPF_PROTOCOL) / \
                PWOSPF_Header(router_id=self.ip, area_id=(self.area),type=PWOSPF_HELLO_TYPE) / PWOSPF_Hello(mask=self.mask, helloint=self.helloint)
            
            self.send_function(hello_packet)
            
    def send_LSU(self):
        lsas = []
        total_links = []
        for interface in self.interfaces:
            neighbors = self.interfaces[interface].get_neighbors()
            for neighbor in neighbors:
                total_links.append((neighbor['router_ip'], neighbor['router_mac'], interface))
                #Generate LSAs
                subnet = ipaddress.ip_network(f"{neighbor['router_ip']}/{self.mask}",strict=False).network_address
                lsa = PWOSPF_LSA(subnet=subnet,mask=self.mask,router_id=neighbor['router_id'])
                lsas.append(lsa)
        
        for ip,mac,interface in total_links:
            OSFP_LSU = Ether(src=self.mac, dst=mac) / CPUMetadata(egressPort=interface) / IP(src=self.ip, dst=ip, proto=PWOSPF_PROTOCOL) / \
                        PWOSPF_Header(router_id=self.ip, area_id=(self.area),type=PWOSPF_LSU_TYPE) / \
                        PWOSPF_LSU(sequence=self.sequence,num_advertisements=len(total_links),link_state_ads=lsas) 
            self.send_function(OSFP_LSU)
        self.sequence += 1
        
        
            
        
            
    def handlePacket(self,pkt):
        # TODO: Check CHECKSUM?
        if pkt[PWOSPF_Header].type == PWOSPF_HELLO_TYPE:
            if pkt[PWOSPF_Hello].mask != self.mask or pkt[PWOSPF_Hello].helloint != self.helloint:
                print("Wrong mask or helloint")
                return
            srcPort = pkt[CPUMetadata].srcPort
            macAddr = pkt[Ether].src
            self.interfaces[srcPort].update_neighbors(pkt[IP].src, pkt[PWOSPF_Header].router_id,macAddr)
            self.send_LSU()
        elif pkt[PWOSPF_Header].type == PWOSPF_LSU_TYPE:
            pkt.show2()
            print(pkt[PWOSPF_LSU].link_state_ads)
            router_id = pkt[PWOSPF_Header].router_id
            # if router_id not in self.LSUS: 
            #     self.LSUS['router_id'] = PWOSPF_LSU()
            
            

    def start(self, *args, **kwargs):
        super(PWOSPF_Router, self).start(*args, **kwargs)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PWOSPF_Router, self).join(*args, **kwargs)
        
    
    