#include <core.p4>
#include <v1model.p4>

// headers

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header mpls_t {
    bit<20> label; // identifies the path
    bit<3>  tc; // traffic class for QoS
    bit<1>  bos; // bottom of stack, indicates if this is the last MPLS header in the stack
    bit<8>  ttl; // time to live, decremented at each hop
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv; // differentiated services, used for QoS (like Type of Service)
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_MPLS = 0x8847;

struct metadata_t { }

// headers_t contains all the headers that the switch can encounter.
struct headers_t {
    ethernet_t ethernet;
    mpls_t     mpls;
    ipv4_t     ipv4;
}

// parser

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std_meta) {
    state start {
        pkt.extract(hdr.ethernet);

        // a transit node can receive both MPLS packets and ipv4 packets (return traffic)

        // if etherType is IPv4, parse IPv4 header
        // if etherType is MPLS, parse MPLS header
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MPLS: parse_mpls;
            default: accept;
        }
    }

    // pkt.extract() reads the specified header fields from the packet and populates the corresponding fields in the hdr struct,
    // after the end the header is marked as valid

    state parse_mpls {
        pkt.extract(hdr.mpls);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// ingress

control MyIngress(inout headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t std_meta) {

    // (1) the apply method consultes the right table (ipv4 or mpls) 
    // (1) based on the header marked as valid by the parser,
    // (2) the table defines, given the packet and its header:
    //     (a) what to match on (the key)
    //     (b) how to match (exact match or longest prefix)
    //     (c) what action to execute 
    //     (d) the default action if no match is found

    action drop() {
        mark_to_drop(std_meta);
    }

    // (2) (c)
    // action params (dstMac, srcMac, port) are provided by the commands_*.txt rules

    action ipv4_forward(bit<48> dstMac, bit<48> srcMac, bit<9> port) {
        hdr.ethernet.dstAddr = dstMac;
        hdr.ethernet.srcAddr = srcMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        std_meta.egress_spec = port;
    }

    
    action mpls_forward(bit<48> dstMac, bit<48> srcMac, bit<9> port) {
        hdr.ethernet.dstAddr = dstMac;
        hdr.ethernet.srcAddr = srcMac;
        hdr.mpls.ttl = hdr.mpls.ttl - 1;
        std_meta.egress_spec = port;
    }

    // (2)

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // longest prefix match
        }
        actions = {
            ipv4_forward;
            drop;
        }
        default_action = drop();
    }

    
    table mpls_exact {
        key = {
            hdr.mpls.label: exact; // exact match on the MPLS label
        }
        actions = {
            mpls_forward;
            drop;
        }
        default_action = drop();
    }

    // (1)
    apply {
        if (hdr.mpls.isValid()) {
            mpls_exact.apply();
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t std_meta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    // when the TTL of ipv4 is decremented, an header field is changed,
    // so the checksum must be recomputed
    // note: only needed if ipv4

    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
              hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

// deparser

control MyDeparser(packet_out pkt, in headers_t hdr) {
    // writes the updated packet headers (only the ones previously set as valid)
    // e.g. if the packet is IPv4, the MPLS header is skipped
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.mpls);
        pkt.emit(hdr.ipv4);
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
