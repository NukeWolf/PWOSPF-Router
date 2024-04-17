# PWOSPF Router

This PWOSPF Router routes packets using the PWOSPF Protocol and also runs a basic arp cache and ethernet l2 layer.

## PWOSPF Protocol
The router sends out Link state updates and Hello messages on a timer using a busy wait. 
- Hello messages get sent out to multicast directory and avoids routing and arp processing.
- Link messages get sent out from interfaces directly and also avoids routing/ arp tables.

Hello messages get caught by the local_ip routing table and get sent directly to software and added to its respective interface.

Link state updates are then flooded according to the protocol. A Link state update class is used to manage advertisements and any changes will result in a routing entry update.

Topology is created from link state advertisements and interface hello message data. A BFS is performed and backtraced to the closest interface. After entries are generated for every available subnet, a manager will replace entries whether or not they change.


## IP Routing and ICMP
A basic lpm routing table is used to route ip packets to other subnets. Packets that miss the ip routing table will be assumed in the local subnet. The Arp_cache will pick up and respond to any ip requests that are not in the subnet. Timeouts result in a time exceeded message, and direct ICMP will be answered by the router.

## ARP Table
By default, ARP requests are automatically responded by the router. The router will then hold the packet and send its own arp request afterwards. Arp requests from other subnets are rejected, so packets don't go to other subnets.

## Structure

- my_topo.py - Can specify num of hosts and switches and also specify links.
- pwospf_packet.py - Packet construction in scapy
- pwospf_router.py - PWOSPF Controller / Thread, handles pkt requests and sends LSUs and Hello messages.
- Controller.py - general controller that responds to ICMP, ARP, general switch management
- arp_handler.py - manages arp entries and table.

## Running

First, make sure you have p4app (which requires Docker):

    cd ~/
    git clone --branch rc-2.0.0 https://github.com/p4lang/p4app.git

Then run this p4app:

    ~/p4app/p4app run maclearning.p4app

On M1 mac, run the run.sh and edit appropriate paths in main.py and run script.




