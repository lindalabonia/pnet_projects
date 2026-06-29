import subprocess
import threading
import time
import sys
import re

# =========================
# PARAMETERS
# =========================
MSS = 1434
IPERF_DURATION = 8

CHAINS = [
    {"name": "Chain 1 (h1 -> h3): SF1 -> SF3 -> SF2",
     "client": "h1", "server": "h3", "server_ip": "10.0.0.3"},
    {"name": "Chain 2 (h2 -> h4): SF3",
     "client": "h2", "server": "h4", "server_ip": "10.0.0.4"},
]

NODES = ["a", "b", "c", "d", "e", "f", "g", "h", "sf1", "sf2", "sf3"]
ROLES = {
    "a": "Transit", "b": "Classifier", "c": "Transit",
    "d": "SFF1", "e": "SFF2", "f": "Transit",
    "g": "Transit", "h": "Transit",
    "sf1": "SF1", "sf2": "SF2", "sf3": "SF3",
}

# =========================
# UTILS
# =========================
def get_container_map():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    mapping = {}
    for name in result.stdout.strip().split("\n"):
        parts = name.split("_")
        if len(parts) >= 2:
            mapping[parts[-2]] = name
    return mapping


def docker_bg(container, cmd):
    subprocess.run(["docker", "exec", "-d", container] + cmd)


# =========================
# CAPTURE & PARSING
# =========================
def run_capture(container, timeout, results, node):
    try:
        r = subprocess.run(
            ["docker", "exec", container,
             "timeout", str(timeout),
             "tcpdump", "-i", "any", "-e", "-n", "-x", "-c", "50"],
            capture_output=True, text=True, timeout=timeout + 5
        )
        results[node] = r.stdout
    except subprocess.TimeoutExpired:
        results[node] = ""


def parse_hex_lines(lines):
    raw = b''
    for line in lines:
        m = re.match(r'\s+0x[0-9a-f]+:\s+(.*)', line)
        if m:
            hex_str = m.group(1).replace(' ', '')
            try:
                raw += bytes.fromhex(hex_str)
            except ValueError:
                pass
    return raw


def analyze_output(output):
    """Parse tcpdump -x output. Returns (mpls_count, ipv4_count, unique_formats).
    For MPLS packets, extracts label from text and NSH spi/si from hex.
    tcpdump -x strips the link-layer header, so hex starts at MPLS:
      offset 0-3: MPLS, offset 4-11: NSH (spi at 8-10, si at 11)"""
    mpls_count = 0
    ipv4_count = 0
    formats = set()

    lines = output.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]

        if not line or line[0].isspace():
            i += 1
            continue

        hex_lines = []
        i += 1
        while i < len(lines) and lines[i].startswith(('\t', '  ')):
            if '0x' in lines[i]:
                hex_lines.append(lines[i])
            i += 1

        if "MPLS" in line:
            mpls_count += 1
            m = re.search(r'label (\d+)', line)
            label = int(m.group(1)) if m else -1

            raw = parse_hex_lines(hex_lines)
            if len(raw) >= 12:
                spi = (raw[8] << 16) | (raw[9] << 8) | raw[10]
                si = raw[11]
                formats.add(f"MPLS label={label} [NSH spi={spi} si={si}]")
            else:
                formats.add(f"MPLS label={label}")

        elif "IPv4" in line or "IP " in line:
            ipv4_count += 1
            formats.add("IPv4")

    return mpls_count, ipv4_count, formats


# =========================
# TEST
# =========================
def run_chain(chain, cmap):
    print(f"\n{'='*55}")
    print(f"  {chain['name']}")
    print(f"{'='*55}")

    srv = cmap.get(chain["server"])
    cli = cmap.get(chain["client"])
    if not srv or not cli:
        print("  container not found")
        return

    docker_bg(srv, ["killall", "iperf3"])
    time.sleep(0.5)
    docker_bg(srv, ["iperf3", "-s", "-D"])
    time.sleep(1)

    # start tcpdump on all nodes
    captures = {}
    threads = []
    for node in NODES:
        c = cmap.get(node)
        if not c:
            continue
        t = threading.Thread(target=run_capture,
                             args=(c, IPERF_DURATION + 2, captures, node))
        t.start()
        threads.append(t)

    time.sleep(1)

    # iperf3
    print(f"\n  iperf3 {chain['client']} -> {chain['server_ip']} (MSS={MSS}, {IPERF_DURATION}s)\n")
    try:
        r = subprocess.run(
            ["docker", "exec", cli,
             "iperf3", "-c", chain["server_ip"], "-M", str(MSS),
             "-t", str(IPERF_DURATION)],
            capture_output=True, text=True, timeout=IPERF_DURATION + 10
        )
        for line in r.stdout.strip().split("\n"):
            if "sender" in line or "receiver" in line:
                print(f"  {line.strip()}")
    except subprocess.TimeoutExpired:
        print("  iperf3 timed out")

    for t in threads:
        t.join()

    docker_bg(srv, ["killall", "iperf3"])

    # packet counts
    print(f"\n  {'Node':<6} {'Role':<12} {'MPLS':>6} {'IPv4':>6}")
    print(f"  {'-'*32}")
    for node in NODES:
        mpls, ipv4, _ = analyze_output(captures.get(node, ""))
        print(f"  {node:<6} {ROLES[node]:<12} {mpls:>6} {ipv4:>6}")

    # packet formats per node
    print(f"\n  Packet formats per node:")
    for node in NODES:
        _, _, fmts = analyze_output(captures.get(node, ""))
        role = ROLES[node]
        if not fmts:
            print(f"  {node:<5} ({role:<11}): -")
        else:
            print(f"  {node:<5} ({role:<11}): {', '.join(sorted(fmts))}")

    # SFF proxy check
    print()
    for sf in ["sf1", "sf2", "sf3"]:
        mpls, ipv4, _ = analyze_output(captures.get(sf, ""))
        if mpls > 0:
            print(f"  FAIL: {sf} saw MPLS (SFF proxy broken)")
        elif ipv4 > 0:
            print(f"  OK: {sf} sees only Eth/IPv4/TCP")


# =========================
# MAIN
# =========================
def main():
    cmap = get_container_map()
    if not cmap:
        print("No containers found. Is Kathara running?")
        sys.exit(1)

    print(f"\n=== SFC Test ===\n")
    print(f"Found {len(cmap)} containers")

    missing = [n for n in NODES + ["h1", "h2", "h3", "h4"] if n not in cmap]
    if missing:
        print(f"Missing: {', '.join(missing)}")

    for chain in CHAINS:
        run_chain(chain, cmap)
        time.sleep(2)

    print(f"\n=== Done ===\n")


if __name__ == "__main__":
    main()
