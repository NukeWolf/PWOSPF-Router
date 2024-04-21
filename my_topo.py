from mininet.topo import Topo
from mininet.link import Link, Intf

class SingleSwitchTopo(Topo):
    def __init__(self, num_switches, num_hosts_per_switch, links, network, **opts):
        Topo.__init__(self, **opts)

        
        self.switch_objs = [self.addSwitch("n%d_s%d" % (network, x)) for x in range(1,num_switches+1)]
        self.extra_links = dict()
        for x in range(1,num_switches+1):
            self.extra_links["n%d_s%d" % (network,x)] = 0
        
        
        for s, switch in enumerate(self.switch_objs):
            for i in range(1, num_hosts_per_switch + 1):
                host = self.addHost(
                    "n%d_s%d_h%d" % (network,s+1,i), ip="10.%d.%d.%d" % (network, s+1,i), mac="00:00:00:%02x:%02x:%02x" % (network, s+1,i)
                )
                self.addLink(host, switch, port2=i)
    

        for s1,s2 in links:
            s1 = self.switch_objs[s1-1]
            s2 = self.switch_objs[s2-1]
            self.addLink(s1,s2)
            self.extra_links[s1] += 1
            self.extra_links[s2] += 1
    def get_switch(self, switch_num):
        self.switch_objs[switch_num-1]
            
