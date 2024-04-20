from threading import Thread
from collections import deque

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
HELLOINT = 5

class PWOSPF_Interface():
    def __init__(self):
        self.NEIGHBOR_TIMEOUT_TIMER = 0
        self.neighbors = []
        
    # Returns true if neighbor existss already.
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
        return found
    def get_neighbors(self):
        return self.neighbors
    
    def get_routing_info(self):
        return [(x['router_id'], x['router_mac']) for x in self.neighbors]
    
    # Returns true if interface has expired
    def update_timer(self):
        self.NEIGHBOR_TIMEOUT_TIMER -= 1
        if self.NEIGHBOR_TIMEOUT_TIMER == 0:
            self.neighbors = []
            return True
        return False
        
    

class PWOSPF_LSU_Data():
    def __init__(self,pkt):
        self.LSU_TIMEOUT_timer = 3
        self.current_sequence = pkt[PWOSPF_LSU].sequence
        self.router_id = pkt[PWOSPF_Header].router_id
        self.router_ip = pkt[IP].src
        
        self.links = []
        
        for lsa in pkt[PWOSPF_LSU].link_state_ads:
            self.links.append({
                'subnet' : lsa.subnet,
                'mask' : lsa.mask,
                'router_id' : lsa.router_id
            })

    # Returns whether data was updated.
    def update_data(self,pkt) -> bool:
        self.LSU_TIMEOUT_timer = 3
        self.current_sequence = pkt[PWOSPF_LSU].sequence
        
        current_links = set(x['router_id'] for x in self.links)
        new_links = []
        new_links_set = set()
        for lsa in pkt[PWOSPF_LSU].link_state_ads:
            new_links.append({
                'subnet' : lsa.subnet,
                'mask' : lsa.mask,
                'router_id' : lsa.router_id
            })
            new_links_set.add(lsa.router_id)
        dif = current_links.symmetric_difference(new_links_set)
        # print(current_links,new_links_set, dif,len(dif))
        
        # No Change
        if len(dif) == 0:
            return False
        else:
            self.links = new_links
            return True
        
    def get_link_routers(self):
        return [x['router_id'] for x in self.links]
    
    def update_timer(self):
        self.LSU_TIMEOUT_timer -= 1
        if self.LSU_TIMEOUT_timer == 0:
            self.links = []
            return True
        return False

    
    
        

        

class PWOSPF_Router(Thread):
    def __init__(self,mac,ip,send,mask,area,num_ports, sw=None):
        super(PWOSPF_Router, self).__init__()
        self.helloint = HELLOINT
        self.helloint_timer = time.time()
        self.mac = mac
        self.id = ip
        self.ip = ip
        self.send_function = send
        self.mask = mask
        self.area = area
        self.sw = sw
        
        
        self.interfaces = dict()
        for x in range(2,num_ports + 2):
            self.interfaces[x] = PWOSPF_Interface()

            
        #LSU Info
        self.sequence = 0
        self.LSUS = dict()
        self.lsuint_timer = time.time()
        
        self.routing_manager = RoutingTableManager(sw,self.mask,self.ip)

    def check_hello_timeout(self):
        for interface in self.interfaces:
            updated = self.interfaces[interface].update_timer()
            if updated:
                self.send_LSU()
        
    def check_LSU_timers(self):
        for link_state_data in self.LSUS:
            self.LSUS[link_state_data].update_timer()

    
    def run(self):
        while True:
            current_time = time.time()
            if current_time - self.helloint > self.helloint_timer:
                self.send_hello()
                self.check_hello_timeout()
                self.helloint_timer = current_time
            if current_time - LSUINT > self.lsuint_timer:
                self.send_LSU()
                
            
    def send_hello(self):
            hello_packet = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff") / CPUMetadata(multicast=1) / IP(src=self.ip, dst=ALLSPFRouters_addr, proto=PWOSPF_PROTOCOL) / \
                PWOSPF_Header(router_id=self.id, area_id=(self.area),type=PWOSPF_HELLO_TYPE) / PWOSPF_Hello(mask=self.mask, helloint=self.helloint)
            
            self.send_function(hello_packet)
            
    def send_LSU(self):
        self.lsuint_timer = time.time()
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
                        PWOSPF_Header(router_id=self.id, area_id=(self.area),type=PWOSPF_LSU_TYPE) / \
                        PWOSPF_LSU(sequence=self.sequence,num_advertisements=len(total_links),link_state_ads=lsas) 
            self.send_function(OSFP_LSU)
        self.sequence += 1
        
        
    def flood(self,pkt):
        # Update TTl and Don't flood if it is 0
        pkt[PWOSPF_LSU].ttl = pkt[PWOSPF_LSU].ttl - 1
        if pkt[PWOSPF_LSU].ttl == 0:
            return
        
        total_links = []
        for interface in self.interfaces:
            neighbors = self.interfaces[interface].get_neighbors()
            for neighbor in neighbors:
                total_links.append((neighbor['router_ip'], neighbor['router_mac'], interface))
        
        # Original Mac Source
        orig_mac = pkt[Ether].src
        pkt[Ether].src = self.mac
        for ip,mac,interface in total_links:
            # Don't send back on original interface
            if mac == orig_mac:
                continue
            pkt[Ether].dst = mac
            pkt[CPUMetadata].egressPort = interface
            pkt[IP].dst = ip

            self.send_function(pkt)
        
        
            
    def handlePacket(self,pkt):
        # TODO: Check CHECKSUM?
        if pkt[PWOSPF_Header].type == PWOSPF_HELLO_TYPE:
            if pkt[PWOSPF_Hello].mask != self.mask or pkt[PWOSPF_Hello].helloint != self.helloint:
                print("Wrong mask or helloint")
                return
            srcPort = pkt[CPUMetadata].srcPort
            macAddr = pkt[Ether].src
            neighbor_exists = self.interfaces[srcPort].update_neighbors(pkt[IP].src, pkt[PWOSPF_Header].router_id,macAddr)
            if not neighbor_exists:
                self.send_LSU()
        elif pkt[PWOSPF_Header].type == PWOSPF_LSU_TYPE:
            # pkt.show2()
            # print(pkt[PWOSPF_LSU].link_state_ads)
            router_id = pkt[PWOSPF_Header].router_id
            if router_id == self.id:
                return
            # if self.id == "10.2.0.1" and router_id == "10.1.0.1":
            #     pkt.show2()
            has_changed = False
            if router_id not in self.LSUS: 
                self.LSUS[router_id] = PWOSPF_LSU_Data(pkt)
                has_changed = True
            else:
                current_LSU = self.LSUS[router_id]
                # TODO: Make this less than so previous packets don't get added?
                if current_LSU.current_sequence == pkt[PWOSPF_LSU].sequence:
                    return
                has_changed = current_LSU.update_data(pkt)
                    
            # Flooding
            self.flood(pkt)
            
            if has_changed:
                entries = self.generate_routing()
                self.routing_manager.update_routing_table(entries)
            

    def start(self, *args, **kwargs):
        super(PWOSPF_Router, self).start(*args, **kwargs)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(PWOSPF_Router, self).join(*args, **kwargs)
        
    
    # Using BFS, gets a lis
    def generate_routing(self):
        start_router = self.id
        all_routers = list(self.LSUS.keys())
        # Queue for BFS
        queue = deque()
        
        # Dictionary to store the parent node of each node in the shortest path
        parent = {}
        for router in all_routers:
            parent[router] = None
        
        neighbor_to_interface_and_mac = dict()
        
        # Initialize the queue with all interfaces
        for port in self.interfaces:
            for neighbor_router_id,mac in self.interfaces[port].get_routing_info():
                neighbor_to_interface_and_mac[neighbor_router_id] = (port,mac)
                if neighbor_router_id in parent:
                    queue.append(neighbor_router_id)
                    parent[neighbor_router_id] = start_router
        
        # print("START Report")
        # print(neighbor_to_interface)
        
        # print(queue)
        # # Main BFS loop
        while queue:
            # Dequeue a node from the queue
            current_node = queue.popleft()
            
            adj_list = self.LSUS[current_node].get_link_routers()
            
            # Traverse all adjacent nodes of the current node
            for neighbor in adj_list:
                if neighbor is start_router:
                    continue
                # If the neighbor node has not been visited yet
                if neighbor in parent and parent[neighbor] is None:
                    # Mark it as visited and Set its parent as the current node
                    parent[neighbor] = current_node
                    # Enqueue the neighbor node for further exploration
                    queue.append(neighbor)
                 
        
        
        routing_entries = dict()
        for router in parent:
            # Not Found, Drop packet
            if parent[router] == None:
                routing_entries[router] = RoutingTableManager.RoutingEntry(router, None, drop=True)
            else:
                # Trace path back to closest interface, and set egress port.
                next_hop_router = router
                while (parent[next_hop_router] != start_router):
                    next_hop_router = parent[next_hop_router]
                routing_entries[router] = RoutingTableManager.RoutingEntry(router, 
                                                                           next_hop_router,
                                                                           port=neighbor_to_interface_and_mac[next_hop_router][0],
                                                                           mac=neighbor_to_interface_and_mac[next_hop_router][1],
                                                                           drop=False)
                (next_hop_router, neighbor_to_interface_and_mac[next_hop_router])
        
        # print(f"~~~~~~~Network of {start_router}~~~~~~~~~~~~~~~")   
        # # print(parent)
        # # print(routing_entries)
        # for x in routing_entries.values():
        #     print(x)
        return routing_entries
        
class RoutingTableManager():
    class RoutingEntry():
        def __init__(self, target_router, next_hop_router, port=None, mac=None, drop=False):
            self.drop = drop
            
            self.next_hop_mac = mac
            self.next_hop_id = next_hop_router
            self.egress_port = port
            
            self.target_subnet = None
            self.target_router = target_router
        def get_target(self):
            return self.target_router
        def get_port_and_mac(self):
            return self.egress_port,self.next_hop_mac
        def is_drop(self):
            return self.drop
        def __str__(self):
            return f"Target: {self.target_router}\nnext_hop_port: {self.egress_port} | next_hop_ip: {self.next_hop_id} | next_hop_mac: {self.next_hop_mac}"
        
        def is_same(self,entry2):
            return entry2.next_hop_mac == self.next_hop_mac and entry2.next_hop_id == self.next_hop_id and entry2.egress_port == self.egress_port
            
    
    def __init__(self, sw, mask, ip, prefix=24,):
        self.entries = dict()
        self.sw = sw
        self.prefix = prefix
        self.mask = mask
        self.ip = ip
        
    def update_routing_table(self,entries):
        current_entries_set = set(self.entries.keys())
        incoming_entries_set = set(entries.keys())
        
        current_entries = self.entries
        incoming_entries = entries
        
        entries_to_remove = current_entries_set.difference(incoming_entries_set)
        entries_to_add = incoming_entries_set.difference(current_entries_set)
        entries_to_change = current_entries_set.intersection(incoming_entries_set)
        
        # print(f"~~~~~~~~~~UPDATE for {self.ip}~~~~~~~~~~")
        # print(entries_to_add)
        # print(entries_to_change)
        # print(entries_to_remove)
        
        for entryKey in entries_to_add:
            entry = incoming_entries[entryKey]
            target = entry.get_target()
            subnet = str(ipaddress.ip_network(f"{target}/{self.mask}",strict=False).network_address)
            
            if entry.is_drop():
                # self.sw.insertTableEntry(table_name='MyIngress.ipv4_routing',
                #     match_fields={'hdr.ipv4.dstAddr': [target, 24]},
                #     action_name='MyIngress.drop',
                #     action_params={})
                pass
            else:
                port,mac = entry.get_port_and_mac()
                self.sw.insertTableEntry(table_name='MyIngress.ipv4_routing',
                    match_fields={'hdr.ipv4.dstAddr': [subnet, self.prefix] },
                    action_name='MyIngress.forward_gateway',
                    action_params={'dst': mac, 'port':port})
                self.entries[entryKey] = entry
            
        for entryKey in entries_to_change:
            entry_old = current_entries[entryKey]
            entry_new = incoming_entries[entryKey]
            target_old = entry_old.get_target()
            target_new = entry_new.get_target()
            subnet_old = str(ipaddress.ip_network(f"{target_old}/{self.mask}",strict=False).network_address)
            subnet_new = str(ipaddress.ip_network(f"{target_new}/{self.mask}",strict=False).network_address)
            
            if entry_old.is_same(entry_new):
                continue
            else:
                print("Deleting")
                port,mac = entry_old.get_port_and_mac()
                self.sw.removeTableEntry(table_name='MyIngress.ipv4_routing',
                    match_fields={'hdr.ipv4.dstAddr': [subnet_old, self.prefix] },
                    action_name='MyIngress.forward_gateway',
                    action_params={'dst': mac, 'port':port})
                
                port,mac = entry_new.get_port_and_mac()
                self.sw.insertTableEntry(table_name='MyIngress.ipv4_routing',
                    match_fields={'hdr.ipv4.dstAddr': [subnet_new, self.prefix] },
                    action_name='MyIngress.forward_gateway',
                    action_params={'dst': mac, 'port':port})
                
                self.entries[entryKey] = entry_new
            
        
        
        
    
    