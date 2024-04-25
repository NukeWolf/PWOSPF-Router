import sys
sys.path.append("/home/whyalex/p4app/docker/scripts")
import time
import itertools
import random

from p4app import P4Mininet

from controller import MacLearningController
from my_topo import SingleSwitchTopo

# Add three hosts. Port 1 (h1) is reserved for the CPU.
NUM_SWITCHES = 8
NUM_HOSTS_PER_SWITCH = 3
AREA = 1
links = [(1,2),(2,3), (2,5), (3,8), (8,4), (4,6), (4,5), (5,7)]

topo = SingleSwitchTopo(NUM_SWITCHES,NUM_HOSTS_PER_SWITCH, links, network=1)
net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

cpus = [] 


for s in range(1,NUM_SWITCHES + 1):
# Add a mcast group for all ports (except for the CPU port)
    bcast_mgid = 1
    sw = net.get("s%d" % s)
    # print(sw)
    sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, NUM_HOSTS_PER_SWITCH + 1 + topo.extra_links["s%d" % s]))

    # Send MAC bcast packets to the bcast multicast group
    sw.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )
    
    
    ports = NUM_HOSTS_PER_SWITCH + topo.extra_links["s%d" % s] - 1
    # Start the MAC learning controller
    cpu = MacLearningController(sw,mac="00:00:00:00:%d:01" % s,ip="10.%d.0.1" % s,area=1, ports=ports, start_wait=1)
    cpu.start()
    cpus.append(cpu)


h2, h3 = net.get("n1_s2_h2"), net.get("n1_s2_h3")
h1 = net.get("n1_s1_h2")

print(h3.cmd("ping -c1 10.2.0.2"))
print(h2.cmd("arp -n"))
print(h3.cmd("ping -c1 10.6.0.2"))

# Wait for router to setup and link state updates to propagate.
time.sleep(30)
print(h3.cmd("ping -c1 10.6.0.2"))
print(h3.cmd("ping -c3 10.4.0.2"))

print(h1.cmd("traceroute -4 10.6.0.2"))
print(h1.cmd("traceroute -4 10.7.0.2"))
print(h1.cmd("ping -c1 10.5.0.1"))


sw = net.get("s%d" % 2)
# These table entries were added by the CPU:
sw.printTableEntries()
