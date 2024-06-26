/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

// ETHERNET Types
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4 = 0x800;



header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<8> multicast;  
    bit<16> egressPort;  
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { 
    ip4Addr_t next_hop_ip;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // TODO: Make sure to put all types in parse_cpu_datatype
    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { 
        verify_checksum(
            hdr.ipv4.isValid(),
            {   // inputs listed as 16bit words 
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                // skp the old csum when computing the new
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    counter(0,CounterType.packets_and_bytes) ip_packets_counter;
    counter(0,CounterType.packets_and_bytes) arp_packets_counter;
    counter(0,CounterType.packets_and_bytes) cpu_packets_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action update_ip_packet(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    
    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu_metadata.multicast = 0;
        hdr.cpu_metadata.egressPort = 0;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
        cpu_packets_counter.count(0);
        exit;
    }

    action set_ether(macAddr_t dst){
        hdr.ethernet.dstAddr = dst;
    }

    action forward_gateway(macAddr_t dst, port_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst;
        exit;
    }
    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }
    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }


    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    table arp_table {
        key = {
            meta.next_hop_ip : exact;
        }
        actions = {
            set_ether;
            drop;
            send_to_cpu;
            NoAction;
        }
        size = 64;
        default_action = send_to_cpu();
    }

    table ipv4_routing {
        key ={
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            forward_gateway;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table local_ip_routing {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            send_to_cpu;
            NoAction;
        }
        size=64;
        default_action = NoAction();
    }

    // By default when arp requests, look for the gateway, if it can't find the gateway.
    // Create a arp request for the control plane. in the control plane.
    //Ip miss in arp table will lead to arp request.
    // Packets will be buffered.
    
    apply {
        
        //From CPU
        if (standard_metadata.ingress_port == CPU_PORT){

            if (hdr.cpu_metadata.multicast == 1){
                set_mgid(1);
                cpu_meta_decap();
                return;
            }
            else if(hdr.cpu_metadata.egressPort != 0){
                set_egr((bit<9>)hdr.cpu_metadata.egressPort);
                cpu_meta_decap();
                return;
            }
            else{
                cpu_meta_decap();
            }
            
        }
            
        if (hdr.ethernet.isValid()) {
            if (hdr.arp.isValid()) {
                arp_packets_counter.count(0);
                if (standard_metadata.ingress_port != CPU_PORT){
                    send_to_cpu();
                }
            }
            else if(hdr.ipv4.isValid()){
                log_msg("IPv4 ttl: {}  | Protocol: {}\n", {hdr.ipv4.ttl,hdr.ipv4.protocol}); 
                ip_packets_counter.count(0);
                update_ip_packet();
                // Error Checks of Packet
                if (hdr.ipv4.ttl == 0 || standard_metadata.checksum_error == 1){
                    send_to_cpu();
                }
                else {
                    // Proceed with IP Resvole
                    local_ip_routing.apply();

                    ipv4_routing.apply();
                    if(meta.next_hop_ip == 0){
                        meta.next_hop_ip = hdr.ipv4.dstAddr;
                    }
                    macAddr_t tempDst = hdr.ethernet.srcAddr;
                    arp_table.apply();

                    hdr.ethernet.srcAddr = tempDst;
                }
                
            }
            // Alternate Ethernet Protocols
            else {
                send_to_cpu();
            }
            fwd_l2.apply();
        }

        
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { 
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
