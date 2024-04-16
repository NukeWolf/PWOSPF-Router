from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ls
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time
import ipaddress



from arp_handler import ArpHandler
from pwospf_router import PWOSPF_Router

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

PWOSPF_PROTOCOL = 89
ALLSPFRouters_addr = "224.0.0.5"



MASK = "255.255.255.0"

class MacLearningController(Thread):
    def __init__(self, sw, mac, ip, area, ports, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.stop_event = Event()
        self.mac = mac
        self.ip = ip
        
        self.subnet = ipaddress.ip_network(f'{self.ip}/{MASK}', strict=False).network_address
        
        self.PWOSPF_handler = PWOSPF_Router(self.mac,self.ip,self.send,MASK,area,ports,sw=sw)
        
        self.arp_table = ArpHandler(sw,self.mac,self.ip)

    def in_gateway(self,ip):
        subnet = ipaddress.ip_network(f'{ip}/{MASK}', strict=False).network_address
        return self.subnet == subnet
    
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return
        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

  
        
        
    def sendArpReply(self,pkt):
        # Ethernet
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = self.mac
        # ARP Modification
        pkt[ARP].op = ARP_OP_REPLY
        pkt[ARP].hwdst = pkt[ARP].hwsrc
        ptemp = pkt[ARP].pdst
        pkt[ARP].pdst = pkt[ARP].psrc
        pkt[ARP].hwsrc = self.mac
        pkt[ARP].psrc = ptemp
        
        self.send(pkt)
        
    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.sendArpReply(pkt)
        
    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
    
    def handlePkt(self, pkt):
        # print("RECIEVE")
        # pkt.show2()
        # print("")
        # if (pkt[Ether].type == 34525):
        #     return
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            # If arp request is not from the same gateway, drop packet.
            if (not self.in_gateway(pkt[ARP].psrc)):
                # print(f"reject arp from {self.ip} to {pkt[ARP].pdst}", )
                return
                
            held_packets = self.arp_table.update_entry(pkt[ARP].psrc,pkt[ARP].hwsrc)
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
                
            for packet in held_packets:
                self.send(packet)
        
        if IP in pkt:
            if pkt[IP].proto == PWOSPF_PROTOCOL:
                # pkt.show2()
                self.PWOSPF_handler.handlePacket(pkt)
                
            elif (self.in_gateway(pkt[IP].dst)):
                if(self.arp_table.is_ip_in_arp_table(pkt[IP].dst)):
                    # TODO: Should be handled but potentially if the ARP_Table boots a packet, that means that something else has been evicted.
                    pass
                else:
                    # Buffers packets
                    arp_req_pkt = self.arp_table.find_mac(pkt)
                    self.send(arp_req_pkt)
            else:
                print("PACKET NOT IN GATEWAY")
                pkt.show2()
                    

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        # print("SEND")
        # pkt.show2()
        # print("")
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        self.sw.insertTableEntry(
            table_name='MyIngress.local_ip_routing',
            match_fields={'hdr.ipv4.dstAddr': [ALLSPFRouters_addr]},
            action_name='MyIngress.send_to_cpu',
            action_params={}
        )
        self.sw.insertTableEntry(
            table_name='MyIngress.local_ip_routing',
            match_fields={'hdr.ipv4.dstAddr': [self.ip]},
            action_name='MyIngress.send_to_cpu',
            action_params={}
        )
        # self.sw.insertTableEntry(table_name='MyIngress.ipv4_routing',
        #             match_fields={'hdr.ipv4.dstAddr': [self.ip, 24]},
        #             action_name='MyIngress.NoAction',
        #             action_params={})
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)
        self.PWOSPF_handler.start()
        
        

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)
