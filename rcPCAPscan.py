import argparse
from scapy.all import PcapReader, IP, TCP, Raw, ICMP, UDP, DNS, DNSQR, ARP
from collections import defaultdict
import numpy as np
import re
import socket
import base64
import time
import geoip2.database
from geoip2.errors import AddressNotFoundError
from collections import Counter
import math
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import socket
import ssl


###########################################################################################
def is_http_request(packet):
    if Raw in packet:
        payload = packet[Raw].load
        return payload.startswith(b'GET ') or payload.startswith(b'POST ') or payload.startswith(b'HEAD ') or payload.startswith(b'PUT ') or payload.startswith(b'DELETE ') or payload.startswith(b'OPTIONS ')

###########################################################################################
def process_pcap(pcap_file, min_interval=1.0):
    connections = defaultdict(list)
    last_time = defaultdict(float)

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and TCP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                dport = packet[TCP].dport
                timestamp = float(packet.time)
                key = (src, dst, dport)

                if is_http_request(packet) and (timestamp - last_time[key]) >= min_interval:
                    connections[key].append(timestamp)
                    last_time[key] = timestamp

    return connections

###########################################################################################
# Detect periodic malware beacons. Need to add ability to detect randomization.
def detect_beacons(pcap_file, threshold=0.99, min_occurrences=5, min_interval=1.0):
    connections = process_pcap(pcap_file, min_interval)

    beacons = []
    print(f"Total connections found: {len(connections)}")

    for (src, dst, dport), timestamps in connections.items():
        print(f"Connection {src} -> {dst}:{dport}: {len(timestamps)} potential beacons")
        if len(timestamps) < min_occurrences:
            continue

        intervals = np.diff(timestamps)

        # Use a histogram to find the most common interval
        hist, bin_edges = np.histogram(intervals, bins='auto')
        most_common_interval = (bin_edges[np.argmax(hist)] + bin_edges[np.argmax(hist) + 1]) / 2

        # Count occurrences of the most common interval (with some tolerance)
        tolerance = 0.1  # 10% tolerance
        occurrences = np.sum((most_common_interval * (1 - tolerance) <= intervals) &
                             (intervals <= most_common_interval * (1 + tolerance)))

        regularity = occurrences / len(intervals)

        print(f"  Most common interval: {most_common_interval:.2f}, Regularity: {regularity:.4f}")

        if regularity > threshold and occurrences >= min_occurrences:
            beacons.append({
                'src': src,
                'dst': dst,
                'dport': dport,
                'count': len(timestamps),
                'interval': most_common_interval,
                'regularity': regularity
            })

    return beacons

#####################################################################################
# Detects the presence of port scans in a pcap
def detect_scans(pcap_file, ping_threshold=5, port_scan_threshold=10, time_window=60):
    ip_counts = defaultdict(lambda: defaultdict(int))
    port_counts = defaultdict(lambda: defaultdict(set))
    scan_start_times = defaultdict(float)

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                timestamp = float(packet.time)

                if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
                    ip_counts[src][dst] += 1
                elif TCP in packet and packet[TCP].flags == 2:  # SYN packet
                    port_counts[src][dst].add(packet[TCP].dport)

                # Update scan start time
                if src not in scan_start_times:
                    scan_start_times[src] = timestamp

                # Check for completed scans
                if timestamp - scan_start_times[src] >= time_window:
                    yield from process_completed_scans(src, ip_counts[src], port_counts[src],
                                                       ping_threshold, port_scan_threshold)
                    ip_counts[src].clear()
                    port_counts[src].clear()
                    scan_start_times[src] = timestamp

    # Process any remaining scans
    for src in ip_counts:
        yield from process_completed_scans(src, ip_counts[src], port_counts[src],
                                           ping_threshold, port_scan_threshold)


###########################################################################################
def process_completed_scans(src, ip_count, port_count, ping_threshold, port_scan_threshold):
    if len(ip_count) >= ping_threshold:
        yield f"Potential ping sweep detected from {src} to {len(ip_count)} hosts"

    for dst, ports in port_count.items():
        if len(ports) >= port_scan_threshold:
            yield f"Potential port scan detected from {src} to {dst} ({len(ports)} ports)"

###########################################################################################
# Detects cleartext use of shell commands indicating potential attacker activity
def detect_shell_commands(pcap_file, command_threshold=1):
    common_commands = [
        'ls', 'cd', 'pwd', 'mkdir', 'rm', 'cp', 'mv', 'cat', 'grep', 'find',
        'chmod', 'chown', 'ps', 'kill', 'top', 'df', 'du', 'free', 'ifconfig',
        'ping', 'netstat', 'ssh', 'scp', 'wget', 'curl', 'sudo', 'apt-get',
        'yum', 'systemctl', 'iptables', 'ufw', 'crontab', 'tar',
        'gzip', 'unzip', 'echo', 'touch', 'sed', 'awk', 'sort', 'uniq', 'wc',
        'vi', 'nano', 'less', 'more', 'tail', 'head', 'tee', 'cut', 'paste',
        'uname', 'whoami', 'hostname', 'ipconfig', 'netstat', 'tasklist', 'net user',
        'localgroup', 'dir', 'attrib', 'runas', 'taskkill', 'sc query', 'sc stop',
        'wmic', 'schtasks', 'powershell', 'certutil', 'bitsadmin', 'wevtutil'
    ]

    command_pattern = r'\b(' + '|'.join(re.escape(cmd) for cmd in common_commands) + r')\b'
    command_regex = re.compile(command_pattern)

    shell_command_packets = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and (TCP in packet or UDP in packet) and Raw in packet:
                payload = packet[Raw].load
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                    matches = command_regex.findall(decoded_payload)

                    if len(matches) >= command_threshold:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        if TCP in packet:
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                        else:  # UDP
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport

                        shell_command_packets.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': 'TCP' if TCP in packet else 'UDP',
                            'commands': matches,
                            'full_command': decoded_payload.strip()
                        })
                except UnicodeDecodeError:
                    # If decoding fails, skip this packet
                    continue

    return shell_command_packets


#####################################################################################
# Identifies the usage of cleartext credentials in network connections
def detect_cleartext_credentials(pcap_file):
    credential_patterns = {
        'HTTP': re.compile(rb'(Authorization: Basic .*|POST.*?username=.*?&.*?password=.*?&)', re.IGNORECASE),
        'FTP': re.compile(rb'(USER|PASS) .*', re.IGNORECASE),
        'POP3': re.compile(rb'(USER|PASS) .*', re.IGNORECASE),
        'TELNET': re.compile(rb'(login:|Login:|Password:).*', re.IGNORECASE),
        'SMTP': re.compile(rb'(AUTH LOGIN|AUTH PLAIN).*', re.IGNORECASE),
        'IMAP': re.compile(rb'(LOGIN|AUTHENTICATE) .*', re.IGNORECASE),
        'Generic': re.compile(rb'(username|password|login|passwd).*=.*', re.IGNORECASE)
    }

    credentials_found = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and (TCP in packet or UDP in packet) and Raw in packet:
                payload = packet[Raw].load
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = 'TCP'
                else:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = 'UDP'

                for proto, pattern in credential_patterns.items():
                    matches = pattern.findall(payload)
                    if matches:
                        try:
                            decoded_payload = payload.decode('utf-8', errors='ignore')
                        except:
                            decoded_payload = str(payload)

                        credentials_found.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'app_protocol': proto,
                            'full_payload': decoded_payload
                        })

    return credentials_found

#####################################################################################
# Provide the total amount of traffic between hosts in bytes
def count_traffic_volume(pcap_file):
    traffic_stats = defaultdict(int)

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                length = len(packet)

                # Count bytes in both directions
                traffic_stats[(src, dst)] += length

    # Sort connections by total bytes (descending order)
    sorted_traffic = sorted(traffic_stats.items(), key=lambda x: x[1], reverse=True)

    return sorted_traffic


#####################################################################################
# Count the number of connections between hosts
def count_connections(pcap_file):
    connection_counts = defaultdict(int)

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst

                # Increment connection count
                connection_counts[(src, dst)] += 1

    # Sort connections by count (descending order)
    sorted_connections = sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)

    return sorted_connections

#####################################################################################
# Detect the use of protocol on unusual port
def detect_protocol_anomalies(pcap_file):
    protocol_signatures = {
        'HTTP': (re.compile(rb'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT) .* HTTP/\d\.\d', re.IGNORECASE), [80, 8080]),
        'HTTPS': (re.compile(rb'^\x16\x03[\x00-\x03].*\x14\x03[\x00-\x03]', re.DOTALL), [443, 8443]),
        'SSH': (re.compile(rb'^SSH-\d\.\d-', re.IGNORECASE), [22]),
        'FTP': (re.compile(rb'^220.*FTP', re.IGNORECASE), [21]),
        'SMTP': (re.compile(rb'^220.*SMTP', re.IGNORECASE), [25, 587]),
        'DNS': (re.compile(rb'^\x00.\x00\x01\x00\x00\x00\x00\x00\x00'), [53]),
        'TELNET': (re.compile(rb'^\xff\xfb|\xff\xfd'), [23]),
    }

    anomalies = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = 'TCP'
                else:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = 'UDP'

                if Raw in packet:
                    payload = packet[Raw].load
                    for proto, (signature, standard_ports) in protocol_signatures.items():
                        if signature.search(payload):
                            if dst_port not in standard_ports:
                                anomalies.append({
                                    'src_ip': src_ip,
                                    'src_port': src_port,
                                    'dst_ip': dst_ip,
                                    'dst_port': dst_port,
                                    'protocol': protocol,
                                    'detected_app_protocol': proto,
                                    'expected_ports': standard_ports
                                })
                            break  # Stop checking other protocols once we've found a match

    return anomalies


#####################################################################################
def analyze_ttl_anomalies(pcap_file, threshold=2):
    ttl_data = defaultdict(list)
    anomalies = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                ttl = packet[IP].ttl
                ttl_data[(src, dst)].append((ttl, packet.time))

    for (src, dst), ttl_list in ttl_data.items():
        if len(ttl_list) > 1:
            ttl_values, timestamps = zip(*ttl_list)
            mean_ttl = np.mean(ttl_values)
            std_ttl = np.std(ttl_values)

            for ttl, timestamp in ttl_list:
                if abs(ttl - mean_ttl) > threshold * std_ttl:
                    anomalies.append({
                        'src': src,
                        'dst': dst,
                        'anomalous_ttl': ttl,
                        'mean_ttl': mean_ttl,
                        'timestamp': timestamp
                    })

    return anomalies


#####################################################################################
def get_endpoints_info(pcap_file, geoip_db_path):
    endpoints = set()

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet:
                endpoints.add(packet[IP].src)
                endpoints.add(packet[IP].dst)

    endpoints_info = []

    # Initialize GeoIP reader
    geoip_reader = geoip2.database.Reader(geoip_db_path)

    for ip in endpoints:
        info = {'ip': ip}

        # DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            info['hostname'] = hostname
        except socket.herror:
            info['hostname'] = 'Unknown'

        # Geolocation
        try:
            geo = geoip_reader.city(ip)
            info['country'] = geo.country.name
            info['city'] = geo.city.name
            info['latitude'] = geo.location.latitude
            info['longitude'] = geo.location.longitude
        except AddressNotFoundError:
            info['country'] = 'Unknown'
            info['city'] = 'Unknown'
            info['latitude'] = 'Unknown'
            info['longitude'] = 'Unknown'

        endpoints_info.append(info)

    geoip_reader.close()
    return endpoints_info


#####################################################################################
def extract_domain_names(pcap_file):
    domains = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet:
                # Check for DNS queries
                if UDP in packet and packet[UDP].dport == 53 and DNS in packet and packet[DNS].qr == 0:
                    if packet[DNS].qd:
                        domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                        domains.append(domain)

                # Check for HTTP/HTTPS traffic
                elif TCP in packet and Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')

                    # Extract Host header from HTTP requests
                    host_match = re.search(r'Host: ([^\r\n]+)', payload)
                    if host_match:
                        domains.append(host_match.group(1))

                    # Extract SNI from TLS Client Hello
                    sni_match = re.search(r'\x00\x00([a-zA-Z0-9.-]+)', payload)
                    if sni_match:
                        domains.append(sni_match.group(1))

    # Count occurrences of each domain
    domain_counts = Counter(domains)

    # Sort domains by count (descending) and then alphabetically
    sorted_domains = sorted(domain_counts.items(), key=lambda x: (-x[1], x[0]))

    return sorted_domains


#####################################################################################
def detect_dns_tunneling(pcap_file, entropy_threshold=3.0, query_threshold=1000):
    dns_queries = defaultdict(list)
    potential_tunnels = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and UDP in packet and packet[UDP].dport == 53 and DNS in packet and packet[DNS].qr == 0:
                if packet[DNS].qd:
                    query = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                    src_ip = packet[IP].src
                    dns_queries[src_ip].append(query)

    for src_ip, queries in dns_queries.items():
        if len(queries) > query_threshold:
            # Calculate average entropy of queries
            avg_entropy = sum(calculate_entropy(q) for q in queries) / len(queries)

            if avg_entropy > entropy_threshold:
                potential_tunnels.append({
                    'src_ip': src_ip,
                    'query_count': len(queries),
                    'avg_entropy': avg_entropy,
                    'sample_queries': queries[:5]  # Include a few sample queries
                })

    return potential_tunnels


def calculate_entropy(string):
    # Calculate the Shannon entropy of a string
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * math.log(p, 2) for p in prob)


#####################################################################################
# Detect ARP spoofing
def detect_arp_spoofing(pcap_file, time_window=10):
    ip_mac_mappings = defaultdict(list)
    potential_spoofing = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if ARP in packet:
                src_ip = packet[ARP].psrc
                src_mac = packet[ARP].hwsrc
                timestamp = float(packet.time)

                ip_mac_mappings[src_ip].append((src_mac, timestamp))

    for ip, mappings in ip_mac_mappings.items():
        # Sort mappings by timestamp
        mappings.sort(key=lambda x: x[1])

        # Check for changes in MAC address within the time window
        prev_mac = None
        start_time = mappings[0][1]

        for mac, timestamp in mappings:
            if prev_mac is None:
                prev_mac = mac
                continue

            if mac != prev_mac and timestamp - start_time <= time_window:
                potential_spoofing.append({
                    'ip': ip,
                    'original_mac': prev_mac,
                    'new_mac': mac,
                    'timestamp': timestamp
                })
                break

            if timestamp - start_time > time_window:
                start_time = timestamp
                prev_mac = mac

    return potential_spoofing


#####################################################################################
def detect_memory_corruption(pcap_file, max_payload_size=1500, shellcode_threshold=0.8):
    potential_exploits = []

    # Simple patterns that might indicate shellcode
    shellcode_patterns = [
        rb'\x90{20,}',  # NOP sled
        rb'(?:\x58|\x59|\x5a|\x5b|\x5c|\x5d|\x5e|\x5f){4,}',  # POP instructions
        rb'\xcc',  # INT3 breakpoint
        rb'\xcd\x80',  # Linux syscall
        rb'\x0f\x34'  # SYSENTER instruction
    ]

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and (TCP in packet or UDP in packet) and Raw in packet:
                payload = packet[Raw].load
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = 'TCP'
                else:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = 'UDP'

                # Check for unusually large payloads
                if len(payload) > max_payload_size:
                    potential_exploits.append({
                        'type': 'Large Payload',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'payload_size': len(payload)
                    })

                # Check for shellcode patterns
                for pattern in shellcode_patterns:
                    if re.search(pattern, payload):
                        potential_exploits.append({
                            'type': 'Potential Shellcode',
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'pattern': pattern
                        })

                # Check for high ratio of non-printable characters
                non_printable = sum(1 for byte in payload if byte < 32 or byte > 126)
                if len(payload) > 0 and non_printable / len(payload) > shellcode_threshold:
                    potential_exploits.append({
                        'type': 'High Non-Printable Ratio',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'non_printable_ratio': non_printable / len(payload)
                    })

    return potential_exploits


#####################################################################################
def detect_ssl_tls_anomalies(pcap_file):
    anomalies = []

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if IP in packet and TCP in packet and packet[TCP].dport == 443 and Raw in packet:
                payload = packet[Raw].load
                if payload.startswith(b'\x16\x03'):  # TLS handshake
                    try:
                        # Extract the certificate from the raw payload
                        # This is a simplified approach and might not work for all TLS versions
                        cert_start = payload.index(b'\x0b') + 3  # Certificate type
                        cert_length = int.from_bytes(payload[cert_start:cert_start + 3], 'big')
                        cert_data = payload[cert_start + 3:cert_start + 3 + cert_length]

                        cert = x509.load_der_x509_certificate(cert_data, default_backend())

                        # Check for self-signed certificate
                        if cert.issuer == cert.subject:
                            anomalies.append({
                                'type': 'Self-signed Certificate',
                                'src_ip': packet[IP].src,
                                'dst_ip': packet[IP].dst,
                                'dst_port': packet[TCP].dport,
                                'subject': cert.subject.rfc4514_string()
                            })

                        # Check for expired certificate
                        if datetime.utcnow() > cert.not_valid_after or datetime.utcnow() < cert.not_valid_before:
                            anomalies.append({
                                'type': 'Expired or Not Yet Valid Certificate',
                                'src_ip': packet[IP].src,
                                'dst_ip': packet[IP].dst,
                                'dst_port': packet[TCP].dport,
                                'subject': cert.subject.rfc4514_string(),
                                'not_before': cert.not_valid_before,
                                'not_after': cert.not_valid_after
                            })

                        # Check for weak signature algorithm
                        if cert.signature_algorithm_oid._name in ['md5WithRSAEncryption', 'sha1WithRSAEncryption']:
                            anomalies.append({
                                'type': 'Weak Signature Algorithm',
                                'src_ip': packet[IP].src,
                                'dst_ip': packet[IP].dst,
                                'dst_port': packet[TCP].dport,
                                'subject': cert.subject.rfc4514_string(),
                                'algorithm': cert.signature_algorithm_oid._name
                            })

                        # Check for short key length
                        public_key = cert.public_key()
                        if hasattr(public_key, 'key_size') and public_key.key_size < 2048:
                            anomalies.append({
                                'type': 'Weak Key Length',
                                'src_ip': packet[IP].src,
                                'dst_ip': packet[IP].dst,
                                'dst_port': packet[TCP].dport,
                                'subject': cert.subject.rfc4514_string(),
                                'key_size': public_key.key_size
                            })

                        # Check for mismatched domain
                        common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                        if common_name != socket.gethostbyaddr(packet[IP].dst)[0]:
                            anomalies.append({
                                'type': 'Mismatched Domain',
                                'src_ip': packet[IP].src,
                                'dst_ip': packet[IP].dst,
                                'dst_port': packet[TCP].dport,
                                'subject': cert.subject.rfc4514_string(),
                                'common_name': common_name,
                                'actual_domain': socket.gethostbyaddr(packet[IP].dst)[0]
                            })

                    except Exception as e:
                        anomalies.append({
                            'type': 'Certificate Parsing Error',
                            'src_ip': packet[IP].src,
                            'dst_ip': packet[IP].dst,
                            'dst_port': packet[TCP].dport,
                            'error': str(e)
                        })

    return anomalies


#####################################################################################
# MAIN
def main():
    parser = argparse.ArgumentParser(description="PCAP Anomaly Scanner")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--detect-beacons", action="store_true", help="Enable beacon detection")
    parser.add_argument("--detect-scans", action="store_true", help="Enable scan detection")
    parser.add_argument("--detect-shell-commands", action="store_true", help="Enable shell command detection")
    parser.add_argument("--threshold", type=float, default=0.9, help="Threshold for beacon detection (0-1)")
    parser.add_argument("--min-occurrences", type=int, default=5, help="Minimum number of occurrences to consider as a beacon")
    parser.add_argument("--min-interval", type=float, default=1.0, help="Minimum interval between beacons (in seconds)")
    parser.add_argument("--ping-threshold", type=int, default=5, help="Minimum number of hosts pinged to consider as a ping sweep")
    parser.add_argument("--port-scan-threshold", type=int, default=10, help="Minimum number of ports scanned to consider as a port scan")
    parser.add_argument("--time-window", type=int, default=60, help="Time window for scan detection (in seconds)")
    parser.add_argument("--command-threshold", type=int, default=1, help="Minimum number of commands in a packet to report")
    parser.add_argument("--detect-credentials", action="store_true", help="Enable cleartext credential detection")
    parser.add_argument("--count-traffic", action="store_true", help="Count total bytes for each connection")
    parser.add_argument("--count-connections", action="store_true", help="Count number of connections between IP pairs")
    parser.add_argument("--detect-protocol-anomalies", action="store_true", help="Detect protocols running on non-standard ports")
    parser.add_argument("--analyze-ttl", action="store_true", help="Analyze TTL anomalies")
    parser.add_argument("--ttl-threshold", type=float, default=2, help="Threshold for TTL anomaly detection (default: 2)")
    parser.add_argument("--list-endpoints", action="store_true", help="List all endpoint IPs with DNS and geolocation info")
    parser.add_argument("--geoip-db", default="GeoLite2-City.mmdb", help="Path to the GeoIP database file")
    parser.add_argument("--extract-domains", action="store_true", help="Extract and list all domain names seen in the PCAP")
    parser.add_argument("--detect-dns-tunneling", action="store_true", help="Detect potential DNS tunneling")
    parser.add_argument("--dns-entropy-threshold", type=float, default=3.0, help="Entropy threshold for DNS tunneling detection")
    parser.add_argument("--dns-query-threshold", type=int, default=1000, help="Query count threshold for DNS tunneling detection")
    parser.add_argument("--detect-arp-spoofing", action="store_true", help="Detect potential ARP spoofing")
    parser.add_argument("--arp-time-window", type=int, default=10, help="Time window (in seconds) for ARP spoofing detection")
    parser.add_argument("--detect-memory-corruption", action="store_true", help="Detect potential memory corruption exploits")
    parser.add_argument("--max-payload-size", type=int, default=1500, help="Maximum expected payload size")
    parser.add_argument("--shellcode-threshold", type=float, default=0.8, help="Threshold for non-printable character ratio")
    parser.add_argument("--detect-ssl-anomalies", action="store_true", help="Detect SSL/TLS anomalies")

    args = parser.parse_args()

    # Detect C2 beacons
    if args.detect_beacons:
        beacons = detect_beacons(args.pcap_file, args.threshold, args.min_occurrences, args.min_interval)
        if beacons:
            print("Potential beacons detected:")
            for beacon in beacons:
                print(f"Source: {beacon['src']}, Destination: {beacon['dst']}:{beacon['dport']}")
                print(f"  Packet count: {beacon['count']}")
                print(f"  Interval: {beacon['interval']:.2f} seconds")
                print(f"  Regularity: {beacon['regularity']:.4f}")
                print()
        else:
            print("No potential beacons detected.")

    # Detect port scans
    if args.detect_scans:
        print("Scanning for potential network scans...")
        scans = list(detect_scans(args.pcap_file, args.ping_threshold, args.port_scan_threshold, args.time_window))
        if scans:
            print("Potential scans detected:")
            for scan in scans:
                print(scan)
        else:
            print("No potential scans detected.")

    # Detect the usage of *nix and windows shell commands over cleartext
    if args.detect_shell_commands:
        print("Scanning for clear text shell commands...")
        shell_commands = detect_shell_commands(args.pcap_file, args.command_threshold)
        if shell_commands:
            print("Potential clear text shell commands detected:")
            for packet in shell_commands:
                print(f"Source: {packet['src_ip']}:{packet['src_port']}, "
                      f"Destination: {packet['dst_ip']}:{packet['dst_port']}, "
                      f"Protocol: {packet['protocol']}")
                print(f"  Commands detected: {', '.join(packet['commands'])}")
                print()
        else:
            print("No clear text shell commands detected.")

    # Detect the usage of cleartext credentials
    if args.detect_credentials:
        print("Scanning for cleartext credentials...")
        credentials = detect_cleartext_credentials(args.pcap_file)
        if credentials:
            print("Potential cleartext credentials detected:")
            for cred in credentials:
                print(f"Source: {cred['src_ip']}:{cred['src_port']}, "
                      f"Destination: {cred['dst_ip']}:{cred['dst_port']}, "
                      f"Protocol: {cred['protocol']}, App Protocol: {cred['app_protocol']}")
                print(f"Full Payload:\n{cred['full_payload']}\n")
        else:
            print("No cleartext credentials detected.")

    # Count the total volume traffic between endpoints
    if args.count_traffic:
        print("\nCounting traffic volume...")
        traffic = count_traffic_volume(args.pcap_file)
        print("Traffic volume statistics:")
        for (src, dst), total_bytes in traffic:
            print(f"{src} -> {dst}  Total Bytes: {total_bytes}")

    # Count the total number of connections between endpoints
    if args.count_connections:
        print("\nCounting connections...")
        connections = count_connections(args.pcap_file)
        print("Connection count statistics:")
        for (src, dst), count in connections:
            print(f"{src} -> {dst} Connection Count: {count}")

    # Detect improper protocol usage
    if args.detect_protocol_anomalies:
        print("\nDetecting protocol anomalies...")
        anomalies = detect_protocol_anomalies(args.pcap_file)
        if anomalies:
            print("Protocol anomalies detected:")
            for anomaly in anomalies:
                print(f"{anomaly['detected_app_protocol']} detected on non-standard port:")
                print(f"  {anomaly['src_ip']}:{anomaly['src_port']} -> {anomaly['dst_ip']}:{anomaly['dst_port']} ({anomaly['protocol']})")
                print(f"  Expected ports: {anomaly['expected_ports']}")
                print()
        else:
            print("No protocol anomalies detected.")

    # Identify TTL anomalies
    if args.analyze_ttl:
        print("\nAnalyzing TTL anomalies...")
        ttl_anomalies = analyze_ttl_anomalies(args.pcap_file, args.ttl_threshold)
        if ttl_anomalies:
            print("TTL anomalies detected:")
            for anomaly in ttl_anomalies:
                print(f"Source: {anomaly['src']}, Destination: {anomaly['dst']}")
                print(f"  Anomalous TTL: {anomaly['anomalous_ttl']}, Mean TTL: {anomaly['mean_ttl']:.2f}")
                print(f"  Timestamp: {anomaly['timestamp']}")
                print()
        else:
            print("No TTL anomalies detected.")

    # List all IPs contacted
    if args.list_endpoints:
        print("\nListing all endpoint IPs with DNS and geolocation info...")
        endpoints_info = get_endpoints_info(args.pcap_file, args.geoip_db)
        for info in endpoints_info:
            print(f"IP: {info['ip']} Hostname: {info['hostname']} Country: {info['country']} City: {info['city']} Latitude: {info['latitude']} Longitude: {info['longitude']}")

    # List all contacted domain names
    if args.extract_domains:
        print("\nExtracting domain names from the PCAP file...")
        domains = extract_domain_names(args.pcap_file)
        if domains:
            print("Domain names found (sorted by frequency):")
            for domain, count in domains:
                print(f"{domain}: {count}")
        else:
            print("No domain names found in the PCAP file.")

    # Detect DNS tunneling
    if args.detect_dns_tunneling:
        print("\nDetecting potential DNS tunneling...")
        tunnels = detect_dns_tunneling(args.pcap_file, args.dns_entropy_threshold, args.dns_query_threshold)
        if tunnels:
            print("Potential DNS tunneling detected:")
            for tunnel in tunnels:
                print(f"Source IP: {tunnel['src_ip']}")
                print(f"  Query Count: {tunnel['query_count']}")
                print(f"  Average Entropy: {tunnel['avg_entropy']:.2f}")
                print("  Sample Queries:")
                for query in tunnel['sample_queries']:
                    print(f"    {query}")
                print()
        else:
            print("No potential DNS tunneling detected.")

    # Detect arp spoofing
    if args.detect_arp_spoofing:
        print("\nDetecting potential ARP spoofing...")
        arp_spoofing = detect_arp_spoofing(args.pcap_file, args.arp_time_window)
        if arp_spoofing:
            print("Potential ARP spoofing detected:")
            for spoof in arp_spoofing:
                if 'original_mac' in spoof:
                    print(f"IP: {spoof['ip']}")
                    print(f"  Original MAC: {spoof['original_mac']}")
                    print(f"  New MAC: {spoof['new_mac']}")
                    print(f"  Timestamp: {spoof['timestamp']}")
                else:
                    print(f"IP: {spoof['ip']} associated with multiple MACs:")
                    for mac in spoof['macs']:
                        print(f"  - {mac}")
                print()
        else:
            print("No potential ARP spoofing detected.")

    # Attempt to detect exploits
    if args.detect_memory_corruption:
        print("\nDetecting potential memory corruption exploits...")
        exploits = detect_memory_corruption(args.pcap_file, args.max_payload_size, args.shellcode_threshold)
        if exploits:
            print("Potential memory corruption exploits detected:")
            for exploit in exploits:
                print(f"Type: {exploit['type']}")
                print(f"Source: {exploit['src_ip']}:{exploit['src_port']}")
                print(f"Destination: {exploit['dst_ip']}:{exploit['dst_port']}")
                print(f"Protocol: {exploit['protocol']}")
                if 'payload_size' in exploit:
                    print(f"Payload Size: {exploit['payload_size']}")
                if 'pattern' in exploit:
                    print(f"Shellcode Pattern: {exploit['pattern']}")
                if 'non_printable_ratio' in exploit:
                    print(f"Non-Printable Ratio: {exploit['non_printable_ratio']:.2f}")
                print()
        else:
            print("No potential memory corruption exploits detected.")

    # Detect SSL/TLS anomalies
    if args.detect_ssl_anomalies:
        print("\nDetecting SSL/TLS anomalies...")
        ssl_anomalies = detect_ssl_tls_anomalies(args.pcap_file)
        if ssl_anomalies:
            print("SSL/TLS anomalies detected:")
            for anomaly in ssl_anomalies:
                print(f"Type: {anomaly['type']}")
                print(f"Source IP: {anomaly['src_ip']}")
                print(f"Destination IP: {anomaly['dst_ip']}:{anomaly['dst_port']}")
                for key, value in anomaly.items():
                    if key not in ['type', 'src_ip', 'dst_ip', 'dst_port']:
                        print(f"{key.capitalize()}: {value}")
                print()
        else:
            print("No SSL/TLS anomalies detected.")


############################################################################
if __name__ == "__main__":
    main()