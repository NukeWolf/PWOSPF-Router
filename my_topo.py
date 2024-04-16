from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    def __init__(self, num_switches, num_hosts_per_switch, **opts):
        Topo.__init__(self, **opts)

        
        switches = [self.addSwitch("s%d" % x) for x in range(1,num_switches+1)]
        self.extra_links = dict()
        for x in range(1,num_switches+1):
            self.extra_links["s%d" % x] = 0
        
        
        for s, switch in enumerate(switches):
            for i in range(1, num_hosts_per_switch + 1):
                host = self.addHost(
                    "s%d_h%d" % (s+1,i), ip="10.%d.0.%d" % (s+1,i), mac="00:00:00:00:%02x:%02x" % (s+1,i)
                )
                self.addLink(host, switch, port2=i)
        
        links = [(1,2),(2,3),(3,1)]
        for s1,s2 in links:
            s1 = switches[s1-1]
            s2 = switches[s2-1]
            self.addLink(s1,s2)
            self.extra_links[s1] += 1
            self.extra_links[s2] += 1
        print(self.extra_links)
            

        
