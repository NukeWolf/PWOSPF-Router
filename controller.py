from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ls
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time


from arp_handler import ArpHandler

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

PWOSPF_PROTOCOL = 89

class MacLearningController(Thread):
    def __init__(self, sw, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.stop_event = Event()
        self.mac = sw.intfs[1].MAC()
        self.ip = sw.intfs[1].IP()
        
        self.arp_table = ArpHandler(sw,self.mac,self.ip)

    def in_gateway(self,pkt):
        return True
    
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
        print("RECIEVE")
        pkt.show2()
        print("")
        # if (pkt[Ether].type == 34525):
        #     return
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            held_packets = self.arp_table.update_entry(pkt[ARP].psrc,pkt[ARP].hwsrc)

            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
                
            for packet in held_packets:
                self.send(packet)
        
        if IP in pkt:
            if (self.in_gateway(pkt)):
                if(self.arp_table.is_ip_in_arp_table(pkt[IP].dst)):
                    # TODO: Should be handled but potentially if the ARP_Table boots a packet, that means that something else has been evicted.
                    pass
                else:
                    # Buffers packets
                    arp_req_pkt = self.arp_table.find_mac(pkt)
                    self.send(arp_req_pkt)
                    
                
    

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        print("SEND")
        pkt.show2()
        print("")
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)
