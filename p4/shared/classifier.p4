#include <core.p4>
#include <v1model.p4>

// headers

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  bos;
    bit<8>  ttl;
}

header nsh_t {
    bit<2>  version;
    bit<1>  oam; // 1 if the packet is for OAM (Operations, Administration, and Maintenance) purposes, 0 otherwise
    bit<1>  unused1;
    bit<6>  ttl;
    bit<6>  length; // length of the NSH header in 4-byte words
    bit<4>  unused2;
    bit<4>  mdType; // 1 for fixed length metadata, 2 for variable length metadata (incuding no metadata)
    bit<8>  nextProto; // protocol of the next header
    bit<24> spi;
    bit<8>  si;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
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
const bit<8> NSH_NEXT_ETHER = 0x03;

struct metadata_t { }

struct headers_t {
    ethernet_t ethernet;
    mpls_t     mpls;
    nsh_t      nsh;
    ethernet_t inner_ethernet;
    ipv4_t     ipv4;
}

// parser

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std_meta) {
    state start {
        pkt.extract(hdr.ethernet);

        // the classifier can receive:
        // - Eth/IPv4/TCP from hosts (new request or normal/return traffic)
        // - Eth/MPLS/NSH/Eth/IPv4/TCP in transit between SFs

        // based on the etherType, apply the correct parsing
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MPLS: parse_mpls;
            default: accept;
        }
    }

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

    action drop() {
        mark_to_drop(std_meta);
    }

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

    // encapsulates a plain Eth/IPv4 packet into Eth/MPLS/NSH/Eth/IPv4
    // action params are provided by the commands_*.txt rules
    action sfc_encapsulate(bit<24> spi, bit<8> si, bit<20> label,
                           bit<48> dstMac, bit<48> srcMac, bit<9> port) {

        // the original Eth header (the hdr.ethernet of the received packet) 
        // becomes the inner Eth (inside the MPLS/NSH tunnel)
        hdr.inner_ethernet.setValid(); 
        hdr.inner_ethernet.dstAddr = hdr.ethernet.dstAddr;
        hdr.inner_ethernet.srcAddr = hdr.ethernet.srcAddr;
        hdr.inner_ethernet.etherType = hdr.ethernet.etherType;

        // create NSH header
        hdr.nsh.setValid();
        hdr.nsh.version = 0;
        hdr.nsh.oam = 0;
        hdr.nsh.unused1 = 0;
        hdr.nsh.unused2 = 0;
        hdr.nsh.ttl = 63; // max value for 6 bits NSH TTL
        hdr.nsh.length = 2; // NSH header length in 4-byte words 
        hdr.nsh.mdType = 2; // MD Type 2 for Metadata length of zero
        hdr.nsh.nextProto = NSH_NEXT_ETHER; // indicates that the next protocol is Ethernet
        hdr.nsh.spi = spi;
        hdr.nsh.si = si;

        // create MPLS header
        hdr.mpls.setValid();
        hdr.mpls.label = label;
        hdr.mpls.tc = 0; // QoS not needed
        hdr.mpls.bos = 1; // bottom of stack 1, since only one MPLS label is used
        hdr.mpls.ttl = 63; // coherent with NSH TTL

        // update outer ethernet
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ethernet.srcAddr = srcMac;

        std_meta.egress_spec = port;
    }

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

    // decides which SFC chain to apply based on src/dst IP
    table sfc_classify {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            sfc_encapsulate;
            NoAction; // if the packet doesn't match any SFC classification rule, apply normal ipv4 forwarding
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.mpls.isValid()) {
            mpls_exact.apply();
        } else if (hdr.ipv4.isValid()) { 
            // either a new request that needs to be classified into an SFC, 
            // or return traffic that needs to be forwarded back to the host,
            // or normal ipv4 traffic that doesn't need to be classified into an SFC

            if (!sfc_classify.apply().hit) {
                // if the packet doesn't match any SFC classification rule, apply normal ipv4 forwarding
                ipv4_lpm.apply();
            }
        }
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta,
                 inout standard_metadata_t std_meta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    // when the TTL of ipv4 is decremented (return or normal traffic), an header fiels is changed,
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

    // outgoing traffic:
    // - Eth/IPv4/TCP for return or plain IPv4 traffic 
    // - Eth/MPLS/NSH/Eth/IPv4/TCP when sending to SFF or in transit between SFs

    apply {
        // it forces the specific correct order (see below) of the headers
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.mpls);
        pkt.emit(hdr.nsh);
        pkt.emit(hdr.inner_ethernet);
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
