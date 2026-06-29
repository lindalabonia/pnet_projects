import time
import statistics
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.addresses import IPAddr
from pox.lib.recoco import Timer

log = core.getLogger()


# STATIC TOPOLOGY (from lab.conf)
TOPOLOGY = {
    'l1': {'mgmt_ip': '20.0.1.1',
           'ports': {1: 'w1',  2: 'w2',  3: 'w3',  4: 'w4',
                     5: 'w5',  6: 'w6',  7: 'w7',  8: 'w11',
                     9: 'w19', 10: 'w25',
                     11: 's1', 12: 's2'}},
    'l2': {'mgmt_ip': '20.0.1.2',
           'ports': {1: 'w8',  2: 'w12', 3: 'w13', 4: 'w14',
                     5: 'w15', 6: 'w16', 7: 'w20', 8: 'w26',
                     9: 's1', 10: 's2'}},
    'l3': {'mgmt_ip': '20.0.1.3',
           'ports': {1: 'c1',  2: 'c2',  3: 'c3',  4: 'c4',
                     5: 's1', 6: 's2'}},
    'l4': {'mgmt_ip': '20.0.1.4',
           'ports': {1: 'w9',  2: 'w17', 3: 'w21', 4: 'w22',
                     5: 'w23', 6: 'w27',
                     7: 's1', 8: 's2'}},
    'l5': {'mgmt_ip': '20.0.1.5',
           'ports': {1: 'w10', 2: 'w18', 3: 'w24', 4: 'w28',
                     5: 's1', 6: 's2'}},
    's1': {'mgmt_ip': '20.0.1.6',
           'ports': {1: 'l1', 2: 'l2', 3: 'l3', 4: 'l4', 5: 'l5'}},
    's2': {'mgmt_ip': '20.0.1.7',
           'ports': {1: 'l1', 2: 'l2', 3: 'l3', 4: 'l4', 5: 'l5'}},
}

HOST_IP = {
    # workers (10.0.0.0/16)
    'w1':  '10.0.0.1',  'w2':  '10.0.0.2',  'w3':  '10.0.0.3',  'w4':  '10.0.0.4',
    'w5':  '10.0.0.5',  'w6':  '10.0.0.6',  'w7':  '10.0.0.7',  'w8':  '10.0.0.8',
    'w9':  '10.0.0.9',  'w10': '10.0.0.10', 'w11': '10.0.0.11', 'w12': '10.0.0.12',
    'w13': '10.0.0.13', 'w14': '10.0.0.14', 'w15': '10.0.0.15', 'w16': '10.0.0.16',
    'w17': '10.0.0.17', 'w18': '10.0.0.18', 'w19': '10.0.0.19', 'w20': '10.0.0.20',
    'w21': '10.0.0.21', 'w22': '10.0.0.22', 'w23': '10.0.0.23', 'w24': '10.0.0.24',
    'w25': '10.0.0.25', 'w26': '10.0.0.26', 'w27': '10.0.0.27', 'w28': '10.0.0.28',
    # collectors (10.0.1.0/16)
    'c1':  '10.0.1.1',  'c2':  '10.0.1.2',  'c3':  '10.0.1.3',  'c4':  '10.0.1.4',
}

# inverted indexes of the above dictionaries for fast lookup
MGMT_IP_TO_NAME = {info['mgmt_ip']: name for name, info in TOPOLOGY.items()} # es: {'20.0.1.1': 'l1', ...}
IP_TO_HOST = {ip: h for h, ip in HOST_IP.items()} # es: {'10.0.0.1': 'w1', ...}
COLLECTOR_IPS = {HOST_IP[c] for c in ('c1', 'c2', 'c3', 'c4')} # es: {'10.0.1.1', '10.0.1.2', ...}
WORKER_IPS = {ip for h, ip in HOST_IP.items() if h.startswith('w')} # es: {'10.0.0.1', '10.0.0.2', ...}

# host -> (leaf_name, port_on_leaf)
# es: {'w1': ('l1', 1), 'w11': ('l1', 8), 'c1': ('l3', 1), ...}
HOST_LOCATION = {}

# leaf -> {spine_name: uplink_port}
# es: {'l1': {'s1': 11, 's2': 12}, 'l3': {'s1': 5, 's2': 6}, ...}
LEAF_UPLINK = {}

# spine -> {leaf_name: downlink_port}
# es: {'s1': {'l1': 1, 'l2': 2, 'l3': 3, 'l4': 4, 'l5': 5}, 's2': {...}}
SPINE_DOWNLINK = {}

for _sw, _info in TOPOLOGY.items():
    for _port, _neigh in _info['ports'].items():
        if _sw.startswith('l') and (_neigh.startswith('w') or _neigh.startswith('c')):
            HOST_LOCATION[_neigh] = (_sw, _port)
        elif _sw.startswith('l') and _neigh.startswith('s'):
            LEAF_UPLINK.setdefault(_sw, {})[_neigh] = _port
        elif _sw.startswith('s') and _neigh.startswith('l'):
            SPINE_DOWNLINK.setdefault(_sw, {})[_neigh] = _port


class FlowTracker(object):
    """Detects transmission rounds for a single worker->collector flow.

    Fed with periodic (time, byte_count) samples via add_sample(). Each
    completed round is appended to self.rounds as a (start_t, bytes) tuple.
    A round is a burst of activity; it is closed only after a sustained
    silence (idle_samples_needed low samples in a row), so short intra-round
    gaps (e.g. TCP retransmissions) don't split one round into two.
    """

    def __init__(self, name, idle_samples_needed, rate_threshold_bps, max_rounds):
        self.name = name                       # "w1->c1", used only for logging
        self.idle_samples_needed = idle_samples_needed
        self.rate_threshold_bps = rate_threshold_bps
        self.max_rounds = max_rounds           # stop observing once this many rounds are captured

        self.prev_t = None                     # last sample seen (time, byte count)
        self.prev_byte = None

        self.in_round = False                  # currently inside a burst?
        self.start_t = None                    # start of the in-progress round -> needed for T and phi
        self.start_byte = None
        self.last_active_byte = None           # byte count at the last active sample
        self.idle_count = 0                    # consecutive idle samples (debounce)

        self.rounds = []                       # completed rounds: list of (start_t, bytes)

    def add_sample(self, t, byte_count):
        if len(self.rounds) >= self.max_rounds:  # captured enough rounds: ignore later samples
            return
        if self.prev_t is None:                # first sample: just record a baseline
            self.prev_t, self.prev_byte = t, byte_count
            return

        dt = t - self.prev_t
        rate = (byte_count - self.prev_byte) * 8 / dt if dt > 0 else 0  # bit per second
        active = rate >= self.rate_threshold_bps

        if active:
            if not self.in_round:              # silence -> activity: open a round
                self.in_round = True
                self.start_t = self.prev_t     # start = previous (still-idle) sample
                self.start_byte = self.prev_byte
            self.last_active_byte = byte_count  # open or extend: remember latest activity
            self.idle_count = 0
        else:
            if self.in_round:                  # silence inside a round
                self.idle_count += 1
                if self.idle_count >= self.idle_samples_needed:   # sustained silence -> close
                    self.rounds.append((self.start_t, self.last_active_byte - self.start_byte))
                    log.info("[ROUND] %s #%d  start=%.1fs  bytes=%d",
                             self.name, len(self.rounds), self.start_t, self.rounds[-1][1])
                    self.in_round = False
            # silence while not in a round: nothing to do

        self.prev_t, self.prev_byte = t, byte_count


class IncastController(object):

    ARP_DEFAULT_SPINE = 's1'   # spine used to forward ARP traffic before any TCP path is installed
    FLOW_PRIORITY = 100        # priority of installed forwarding rules
    POLL_INTERVAL_S = 0.2      # period (s) between flow-stats polls 
    BURST_RATE_THRESHOLD_BPS = 100_000 # min throughput (bps) to consider a sample part of a burst
    LINK_CAPACITY_MBPS = 100
    ROUND_IDLE_GAP_S = 3.0     # sustained idle before a round is considered finished (debounce)
    ROUNDS_TO_OBSERVE = 3      # completed rounds per flow before inferring 

    def __init__(self):
        core.openflow.addListeners(self)

        # populated at ConnectionUp 
        self.dpid_to_name = {}    # es: {dpid1: 'l1', ...}
        self.name_to_dpid = {}    # es: {'l1': dpid1, ...}

        # learned from ARP
        # es: {'w1': '00:00:00:00:00:01', 'c1': '00:00:00:00:00:11', ...}
        self.host_mac = {}

        # spine chosen for each (worker, collector) pair
        # es: {('w1', 'c1'): 's1', ('w2', 'c1'): 's2', ...}
        self.spine_assignment = {}

        # round-robin counter per collector (used to alternate S1/S2)
        # es: {'c1': 3, 'c2': 1, ...}
        self.rr_counter = {c: 0 for c in HOST_IP if c.startswith('c')}

        # discovered workers per training collector
        # es: {'c1': {'w1', 'w2', ...}, 'c2': {...}, ...}
        self.training_workers = {c: set() for c in HOST_IP if c.startswith('c')}

        # (worker, collector) pairs for which rules are already installed.
        # Guards against duplicate packet_ins on flow startup, so we don't
        # advance the round-robin counter, reinstall rules etc.
        # es: {('w1', 'c1'), ('w2', 'c2'), ...}
        self.paths_installed = set()

        # reference timestamp used to convert wall-clock time into seconds
        # since the controller started (more readable in logs and inference)
        self.start_time = time.time()

        # time (in seconds since start_time) of the first worker->collector
        # packet ever observed. Used as the common origin for phi, so phases
        # are measured from "when traffic began", not from controller boot.
        self.traffic_origin = None

        # one FlowTracker per flow: {(worker, collector): FlowTracker}.
        # Each tracker consumes flow-stats samples and exposes the rounds it detects.
        self.flow_state = {}

        # number of consecutive idle samples that make up ROUND_IDLE_GAP_S:
        # a round is closed only after this many low samples in a row, so short
        # intra-round gaps (TCP retransmissions) don't split one round in two.
        self._idle_samples_needed = max(1, round(self.ROUND_IDLE_GAP_S / self.POLL_INTERVAL_S))

        # inferred traffic parameters per training collector
        # es: {'c1': {'K_v': 10, 'D_v': 50.0, 'phi_v': 1.0, 'T_v': 30.0}, ...}
        self.training_params = {}

        # optimized worker->spine assignment, computed once when all trainings are inferred
        # es: {('w1', 'c1'): 's1', ('w2', 'c1'): 's2', ...}
        self.optimized_assignment = None

        # periodic flow-stats polling 
        Timer(self.POLL_INTERVAL_S, self._poll_stats, recurring=True)

        log.info("=== IncastController ready ===")
        log.info("Topology: %d switches, %d hosts (%d collectors)",
                 len(TOPOLOGY), len(HOST_IP), len(COLLECTOR_IPS))

    def _handle_ConnectionUp(self, event):
        # Identify the switch by the source IP of its OpenFlow connection
        try:
            peer_ip = event.connection.sock.getpeername()[0]
        except Exception as e:
            log.warning("Cannot read peer IP for dpid=0x%x: %s", event.dpid, e)
            return
        
        name = MGMT_IP_TO_NAME.get(peer_ip)
        if name is None:
            log.warning("Unknown switch connected from %s (dpid=0x%x)",
                        peer_ip, event.dpid)
            return
        
        self.dpid_to_name[event.dpid] = name
        self.name_to_dpid[name] = event.dpid
        log.info("Switch %s connected from %s (dpid=0x%x)",
                 name, peer_ip, event.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        sw_name = self.dpid_to_name.get(event.dpid)
        if sw_name is None:
            return

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet, sw_name)
            return

        if packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.payload
            if isinstance(ip_pkt, ipv4) and isinstance(ip_pkt.payload, tcp):
                # we care only about TCP traffic, generated by iperf3
                self._handle_tcp(event, ip_pkt)

    def _handle_arp(self, event, packet, sw_name):
        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        dst_ip = str(arp_pkt.protodst)

        # Learn sender MAC
        if src_ip in IP_TO_HOST:
            host = IP_TO_HOST[src_ip]
            if host not in self.host_mac:
                self.host_mac[host] = packet.src
                #log.info("[ARP] learned %s (%s) -> %s", host, src_ip, packet.src)

        if arp_pkt.opcode == arp.REQUEST:
            target_host = IP_TO_HOST.get(dst_ip)
            if target_host is not None and target_host in self.host_mac:
                # We know the target MAC: reply on behalf of the target
                self._send_arp_reply(event, arp_pkt, self.host_mac[target_host])
                return
            # Otherwise: forward the request unicast toward target leaf
            self._forward_arp(event, dst_ip, sw_name)

        elif arp_pkt.opcode == arp.REPLY:
            # Forward the reply unicast back toward the original requester
            self._forward_arp(event, dst_ip, sw_name)

    def _send_arp_reply(self, event, arp_req, target_mac):
        reply = arp()
        reply.hwtype = arp_req.hwtype # ethernet
        reply.prototype = arp_req.prototype # IPv4
        reply.hwlen = arp_req.hwlen # ethernet address length
        reply.protolen = arp_req.protolen # IPv4 address length
        reply.opcode = arp.REPLY
        reply.hwdst = arp_req.hwsrc # send the reply to the original requester
        reply.protodst = arp_req.protosrc
        reply.hwsrc = target_mac #send the reply as if it came from the target host
        reply.protosrc = arp_req.protodst

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.dst = arp_req.hwsrc
        eth.src = target_mac
        eth.payload = reply

        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        # NOTE: in_port is intentionally NOT set: output port == request's input port,
        # so setting in_port would trigger the anti-loop check and drop the reply.
        msg.actions.append(of.ofp_action_output(port=event.port)) # send the reply back to the port where the request came from
        event.connection.send(msg)

    def _forward_arp(self, event, dst_ip, sw_name):

        # sw_name is the switch where the ARP packet was received. 
        # We need to determine the output port to forward the ARP packet toward the target host.
        
        target_host = IP_TO_HOST.get(dst_ip)
        if target_host is None:
            return
        target_leaf, target_port = HOST_LOCATION[target_host]

        if sw_name == target_leaf: 
            # The ARP packet is already at the leaf where the target host is connected, 
            # so we can send it directly to the target port.
            out_port = target_port
        elif sw_name.startswith('l'):
            # The ARP packet is at a leaf switch != target leaf, so we need to forward it to the default spine
            out_port = LEAF_UPLINK[sw_name][self.ARP_DEFAULT_SPINE]
        elif sw_name.startswith('s'):
            # The ARP packet is at a spine switch, so we need to forward it down to the target leaf
            out_port = SPINE_DOWNLINK[sw_name][target_leaf]
        else:
            return

        log.debug("[ARP fwd] %s for %s on %s -> port %d",
                  "REQ" if event.parsed.payload.opcode == arp.REQUEST else "REPLY",
                  dst_ip, sw_name, out_port)

        msg = of.ofp_packet_out()
        msg.data = event.ofp.data   # always use the raw packet bytes (robust to buffer expiration)
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _handle_tcp(self, event, ip_pkt):
        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)

        # We only care about worker -> collector traffic
        if dst_ip not in COLLECTOR_IPS or src_ip not in WORKER_IPS:
            return

        worker_name = IP_TO_HOST[src_ip]
        collector_name = IP_TO_HOST[dst_ip]

        # the very first worker->collector packet defines the common time origin
        if self.traffic_origin is None:
            self.traffic_origin = time.time() - self.start_time
            log.info("[ORIGIN] traffic started at t=%.1fs (controller-relative)",
                     self.traffic_origin)

        if worker_name not in self.training_workers[collector_name]: # worker not yet discovered
            self.training_workers[collector_name].add(worker_name)
            log.info("[DISCOVERY] training@%s: +%s  (K=%d)",
                     collector_name, worker_name,
                     len(self.training_workers[collector_name]))

        # installation of flow rules in path worker <-> collector for observation phase
        key = (worker_name, collector_name)
        if key not in self.paths_installed:
            spine = self._assign_spine(collector_name) # choose S1/S2 in round-robin fashion 
            self.spine_assignment[key] = spine
            self._install_path(worker_name, collector_name, spine)
            self.paths_installed.add(key)
            log.info("[PATH] %s -> %s via %s",
                     worker_name, collector_name, spine.upper())

        # Re-send the pkt that triggered the PacketIn so it isn't dropped: OFPP_TABLE
        # makes the switch process the packet through the (just installed) flow table.
        self._send_via_table(event)

    def _assign_spine(self, collector_name):
        # Round-robin S1/S2 per collector
        # Even count -> S1, odd -> S2
        idx = self.rr_counter[collector_name] % 2
        self.rr_counter[collector_name] += 1
        return 's1' if idx == 0 else 's2'

    def _install_path(self, worker_name, collector_name, spine):
        # Install bidirectional flow rules along the chosen spine
        worker_ip = HOST_IP[worker_name]
        collector_ip = HOST_IP[collector_name]

        # get the leaf switch and the port on that leaf where the worker and collector are connected
        w_leaf, w_port = HOST_LOCATION[worker_name]
        c_leaf, c_port = HOST_LOCATION[collector_name]

        # forward: worker -> leaf -> spine -> collector
        self._install_rule(w_leaf, worker_ip, collector_ip, LEAF_UPLINK[w_leaf][spine])
        self._install_rule(spine, worker_ip, collector_ip, SPINE_DOWNLINK[spine][c_leaf])
        self._install_rule(c_leaf, worker_ip, collector_ip, c_port)

        # reverse: collector -> leaf -> spine -> worker
        self._install_rule(c_leaf, collector_ip, worker_ip, LEAF_UPLINK[c_leaf][spine])
        self._install_rule(spine, collector_ip, worker_ip, SPINE_DOWNLINK[spine][w_leaf])
        self._install_rule(w_leaf, collector_ip, worker_ip, w_port)

    def _install_rule(self, sw_name, src_ip, dst_ip, out_port):
        # on the switch sw_name, install a flow rule that matches packets from src_ip to dst_ip 
        # and forwards them to out_port
        dpid = self.name_to_dpid.get(sw_name)
        if dpid is None:
            log.warning("[FLOW] %s not yet connected, skip rule", sw_name)
            return
        conn = core.openflow.getConnection(dpid)
        if conn is None:
            log.warning("[FLOW] no connection for %s (dpid=0x%x)", sw_name, dpid)
            return
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800        # IPv4
        msg.match.nw_src = IPAddr(src_ip)
        msg.match.nw_dst = IPAddr(dst_ip)
        msg.priority = self.FLOW_PRIORITY
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.actions.append(of.ofp_action_output(port=out_port))
        conn.send(msg)

    def _send_via_table(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp.data
        msg.in_port = event.port

        # OFPP_TABLE is a special virtual port for OpenFlow. When used as action output port,
        # it means "take the packet and send it into the switch's flow table as if it had just arrived on the specified in_port,
        # then process it as normal (look for a matching rule)".
        msg.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
        event.connection.send(msg)

    def _poll_stats(self):
        # Ask every worker leaf (l1, l2, l4, l5) for its flow stats.
        # l3 holds the collectors and would give us duplicate data for the same flows.
        for leaf in ('l1', 'l2', 'l4', 'l5'):
            dpid = self.name_to_dpid.get(leaf)
            if dpid is None:
                continue
            conn = core.openflow.getConnection(dpid)
            if conn is None:
                continue
            req = of.ofp_stats_request()
            req.body = of.ofp_flow_stats_request()
            req.body.match = of.ofp_match()  # match all flows
            req.body.table_id = 0xff # match all tables (there's only one anyway)
            req.body.out_port = of.OFPP_NONE # no out_port filter
            conn.send(req)

    def _handle_FlowStatsReceived(self, event):
        sw_name = self.dpid_to_name.get(event.dpid)
        if sw_name is None or sw_name not in ('l1', 'l2', 'l4', 'l5'):
            return
        now = time.time() - self.start_time # time origin t=0 at controller startup, in seconds 

        # collectors whose state was updated this round 
        touched_collectors = set()

        for stat in event.stats:
            nw_src = stat.match.nw_src
            nw_dst = stat.match.nw_dst
            if nw_src is None or nw_dst is None:
                continue
            src_ip = str(nw_src)
            dst_ip = str(nw_dst)
            # we only track worker -> collector flows
            if src_ip not in WORKER_IPS or dst_ip not in COLLECTOR_IPS:
                continue
            worker_name = IP_TO_HOST[src_ip]
            collector_name = IP_TO_HOST[dst_ip]
            key = (worker_name, collector_name)

            self._update_flow_state(key, now, stat.byte_count)
            touched_collectors.add(collector_name)

        # trigger inference only when a training is fully observed (2 rounds done)
        # and we haven't already inferred it
        for collector_name in touched_collectors:
            if (collector_name not in self.training_params and self._is_observation_complete(collector_name)):
                self._infer_params(collector_name)

        # once all trainings have been inferred, compute and apply optimized assignment
        self._optimize()

    def _update_flow_state(self, key, curr_t, curr_byte):
        # Feed one flow-stats sample to this flow's tracker, creating it on first sight.
        tracker = self.flow_state.get(key)
        if tracker is None:
            name = "%s->%s" % (key[0], key[1])
            tracker = FlowTracker(name, self._idle_samples_needed,
                                  self.BURST_RATE_THRESHOLD_BPS, self.ROUNDS_TO_OBSERVE)
            self.flow_state[key] = tracker
        tracker.add_sample(curr_t, curr_byte)

    def _is_observation_complete(self, collector_name):
        # True once every worker of the training has captured ROUNDS_TO_OBSERVE rounds
        workers = self.training_workers[collector_name]
        if not workers:
            return False
        for worker_name in workers:
            tracker = self.flow_state.get((worker_name, collector_name))
            if tracker is None or len(tracker.rounds) < self.ROUNDS_TO_OBSERVE:
                return False
        return True

    def _infer_params(self, collector_name):
        # Estimate K, D, T, phi for a training. Assumes the training is complete
        # (caller guarantees every worker has ROUNDS_TO_OBSERVE rounds captured).
        
        workers = self.training_workers[collector_name]
        trackers = [self.flow_state[(w, collector_name)] for w in workers]
        K_v = len(workers)

        # D_v: median bytes per round over all rounds of all workers.
        # Median (not mean) so an occasional merged round (~2x bytes, when the
        # idle gap between two real rounds wasn't fully observed) doesn't inflate D.
        all_round_bytes = [bytes_ for tr in trackers for (_start, bytes_) in tr.rounds]
        D_bytes = statistics.median(all_round_bytes)
        D_v = D_bytes * 8 / 1e6

        # phi_v: phase of the first round, measured from the common traffic
        # origin (first packet seen), so it is comparable across trainings and
        # independent of when the controller booted.
        origin = self.traffic_origin or 0.0
        phi_v = min(tr.rounds[0][0] for tr in trackers) - origin

        # T_v: smallest spacing between consecutive round starts, pooled across
        # workers. A missed round only enlarges a gap (to ~2x/3x T), never shrinks
        # it, so the minimum gap is the best estimate of a single period.
        gaps = []
        for tr in trackers:
            starts = [start for (start, _bytes) in tr.rounds]
            for i in range(1, len(starts)):
                gaps.append(starts[i] - starts[i-1])
        T_v = min(gaps) if gaps else 0.0

        self.training_params[collector_name] = {
            'K_v': K_v,
            'D_v': D_v,      # Mbit
            'phi_v': phi_v,  # seconds
            'T_v': T_v,      # seconds
        }
        log.info("[PARAMS] %s: K=%d  D=%.1f Mbit  T=%.1fs  phi=%.1fs",
                 collector_name, K_v, D_v, T_v, phi_v)

    def _optimize(self):
        # Run optimization once, when all trainings have been inferred.
        
        if self.optimized_assignment is not None:
            return
        if len(self.training_params) < len(COLLECTOR_IPS):
            return

        # peak per-worker throughput when its training is active (= C_v / K_v).
        # Same for all workers of the same training, so compute once per collector.
        rate_per_collector = {}
        for c, params in self.training_params.items():
            rate_per_collector[c] = self.LINK_CAPACITY_MBPS / params['K_v']

        # group workers by their leaf, and compute the total peak load on each leaf
        workers_on_leaf = {}      # leaf -> list of (worker, collector, rate)
        leaf_load = {}            # leaf -> total Mbps at peak (all workers transmitting)
        for collector_name, rate in rate_per_collector.items():
            for worker_name in self.training_workers[collector_name]:
                leaf = HOST_LOCATION[worker_name][0]
                workers_on_leaf.setdefault(leaf, []).append((worker_name, collector_name, rate))
                leaf_load[leaf] = leaf_load.get(leaf, 0) + rate

        # sort each leaf's workers by rate desc
        for workers in workers_on_leaf.values():
            workers.sort(key=lambda w: w[2], reverse=True) 

        # global load counters on each spine
        s1_load = 0.0
        s2_load = 0.0
        assignment = {}

        # process leaves heaviest first, then their workers heaviest first.
        # Each worker goes to the spine with the lower current load.
        for leaf in sorted(leaf_load, key=leaf_load.get, reverse=True):
            for worker_name, collector_name, rate in workers_on_leaf[leaf]:
                if s1_load <= s2_load:
                    assignment[(worker_name, collector_name)] = 's1'
                    s1_load += rate
                else:
                    assignment[(worker_name, collector_name)] = 's2'
                    s2_load += rate

        log.info("[OPTIMIZE] LPT result: S1=%.1f Mbps  S2=%.1f Mbps", s1_load, s2_load)
        self.optimized_assignment = assignment
        self._apply_assignment(assignment)

    def _apply_assignment(self, new_assignment):
        # Migrate workers whose spine changed.
        # Order matters: install on new spine BEFORE redirecting leaf traffic to it,
        # then clean up old spine. This avoids any "no rule" window for in-flight packets.
        
        changed = 0
        for (worker_name, collector_name), new_spine in new_assignment.items():
            old_spine = self.spine_assignment.get((worker_name, collector_name))
            if old_spine == new_spine:
                continue

            # (re)install all 6 rules along the new path; existing leaf rules
            # with the same match are simply overwritten (idempotent)
            self._install_path(worker_name, collector_name, new_spine)

            if old_spine is not None:
                worker_ip = HOST_IP[worker_name]
                collector_ip = HOST_IP[collector_name]
                self._delete_rule(old_spine, worker_ip, collector_ip)
                self._delete_rule(old_spine, collector_ip, worker_ip)

            self.spine_assignment[(worker_name, collector_name)] = new_spine
            changed += 1
            log.info("[MIGRATE] %s -> %s: %s -> %s",
                     worker_name, collector_name,
                     old_spine.upper() if old_spine else '?',
                     new_spine.upper())
        log.info("[OPTIMIZE] %d/%d worker assignments changed",
                 changed, len(new_assignment))

    def _delete_rule(self, sw_name, src_ip, dst_ip):
        # Remove the rule matching exactly (src_ip, dst_ip) at FLOW_PRIORITY.
        # Used on the old spine after a worker has been migrated.
        
        dpid = self.name_to_dpid.get(sw_name)
        if dpid is None:
            log.warning("[FLOW] %s not connected, skip delete", sw_name)
            return
        conn = core.openflow.getConnection(dpid)
        if conn is None:
            return
        msg = of.ofp_flow_mod()
        msg.command = of.OFPFC_DELETE_STRICT
        msg.match.dl_type = 0x0800
        msg.match.nw_src = IPAddr(src_ip)
        msg.match.nw_dst = IPAddr(dst_ip)
        msg.priority = self.FLOW_PRIORITY
        conn.send(msg)


def launch():
    core.registerNew(IncastController)
