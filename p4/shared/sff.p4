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
    bit<1>  oam;
    bit<1>  unused1;
    bit<6>  ttl;
    bit<6>  length;
    bit<4>  unused2;
    bit<4>  mdType;
    bit<8>  nextProto;
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

        // the SFF can receive:
        // - Eth/MPLS/NSH/Eth/IPv4 -> SFC traffic from another node -> send to a local SF or forward it
        // - Eth/IPV4 -> packet returning from SF port (re-encapsulate and forward or end chain)
        //               or plain IPv4 transit traffic from network port (forward like a transit node)
        
        transition select(hdr.ethernet.etherType) {
            TYPE_MPLS: parse_mpls;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_mpls {
        pkt.extract(hdr.mpls);
        transition parse_nsh;
    }

    state parse_nsh {
        pkt.extract(hdr.nsh);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
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

    // strip MPLS/NSH, restore original packet from inner_eth, send to SF.
    // the SF (reflector) receives the original Eth with the host MACs from when
    // the classifier encapsulated the packet. BMv2 simple_switch does not do MAC
    // filtering, so the SF accepts it regardless of dst MAC.
    // the reflector swaps src/dst MACs and sends back — this allows
    // restore_and_forward to reconstruct inner_eth by swapping them again.
    action send_to_sf(bit<9> port) {
        hdr.ethernet.dstAddr = hdr.inner_ethernet.dstAddr;
        hdr.ethernet.srcAddr = hdr.inner_ethernet.srcAddr;
        hdr.ethernet.etherType = hdr.inner_ethernet.etherType;
        hdr.mpls.setInvalid();
        hdr.nsh.setInvalid();
        hdr.inner_ethernet.setInvalid();
        std_meta.egress_spec = port;
    }

    // MPLS/NSH transit: not for this SFF, just forward like a transit node
    action mpls_forward(bit<48> dstMac, bit<48> srcMac, bit<9> port) {
        hdr.mpls.ttl = hdr.mpls.ttl - 1;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ethernet.srcAddr = srcMac;
        std_meta.egress_spec = port;
    }

    // re-encapsulate packet returning from SF, forward to next SFF.
    // inner_eth MACs are reconstructed by swapping the ethernet MACs back
    // (the reflector swapped them, so src↔dst restores the originals)
    action restore_and_forward(bit<24> spi, bit<8> si, bit<20> label,
                               bit<48> dstMac, bit<48> srcMac, bit<9> port) {
        hdr.inner_ethernet.setValid();
        hdr.inner_ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.inner_ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.inner_ethernet.etherType = TYPE_IPV4;

        hdr.nsh.setValid();
        hdr.nsh.version = 0;
        hdr.nsh.oam = 0;
        hdr.nsh.unused1 = 0;
        hdr.nsh.unused2 = 0;
        hdr.nsh.ttl = 63;
        hdr.nsh.length = 2;
        hdr.nsh.mdType = 2;
        hdr.nsh.nextProto = NSH_NEXT_ETHER;
        hdr.nsh.spi = spi;
        hdr.nsh.si = si - 1; // decrement SI to indicate progress in the chain

        hdr.mpls.setValid();
        hdr.mpls.label = label;
        hdr.mpls.tc = 0;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 63;

        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ethernet.srcAddr = srcMac;

        std_meta.egress_spec = port;
    }

    // chain is done after last SF, forward as plain IPv4
    action end_chain(bit<48> dstMac, bit<48> srcMac, bit<9> port) {
        hdr.ethernet.dstAddr = dstMac;
        hdr.ethernet.srcAddr = srcMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        std_meta.egress_spec = port;
    }

    // when SFF receives MPLS/NSH traffic, match on SPI+SI to decide what to do
    table nsh_forward {
        key = {
            hdr.nsh.spi: exact;
            hdr.nsh.si:  exact;
        }
        actions = {
            send_to_sf;
            mpls_forward;
            drop;
        }
        default_action = drop();
    }

    // when a packet returns from an SF (Eth/IPv4),
    // match on ingress port (identifies from which SF the packet is returning) 
    // + IP src/dst (identify the chain) to decide what to do
    table sf_return {
        key = {
            std_meta.ingress_port: exact; 
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            restore_and_forward;
            end_chain;
            drop;
        }
        default_action = drop();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        default_action = drop();
    }

    apply {
        if (hdr.nsh.isValid()) { // MPLS and NSH are parsed together, so if NSH is valid, MPLS is valid too
            nsh_forward.apply();
        } else if (hdr.ipv4.isValid()) {
            // packet from SF or plain IPv4 transit traffic
            if (!sf_return.apply().hit) {
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
