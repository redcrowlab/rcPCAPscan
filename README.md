# rcPCAPscan 
###################################################

Red Crow Lab

###################################################

## DESCRIPTION

Scans a PCAP file looking for anomalies.

- Beacons
- Port scans
- Cleartext shell commands
- Cleartext credentials
- Count connections & traffic volume
- Protocol anomalies
- TTL anomalies
- Endpoint Information
- Extract all domain names
- Detect DNS tunneling
- Detect ARP spoofing
- Detect memory corruption
- Detect SSL/TLS anomalies 

## INSTALL

```
git clone http://gitlab.redcrowlab.com/asclark/rcpcapscan.git

pip install -r requirements.txt

```

## USAGE

Search for HTTP/S beacons that use either GET or POST. Can find beacons on non-standard ports:
```
python rcPCAPscan.py --detect-beacons --threshold 0.9 --min-occurrences 5 --min-interval 1 http_beacon_POST_SSL_example.pcapng
```
Search for port scans:
```
python rcPCAPscan.py --detect-scans --ping-threshold 5 --port-scan-threshold 10 --time-window 60 portscan_detect_example.pcapng
```
Search for cleartext shell commands (windows and *nix):
```
python rcPCAPscan.py --detect-shell-commands --command-threshold 1 shell_example.pcapng
```
Search for cleartext credentials:
```
python rcPCAPscan.py cleartext_creds.pcapng --detect-credentials
```
Count total connections as well as total traffic volume between hosts:
```
python rcPCAPscan.py cleartext_creds.pcapng --count-connections --count-traffic
```
Detect the anomalous use of protocols on unusual ports:
```
python rcPCAPscan.py cleartext_creds.pcapng --detect-protocol-anomalies
```
Search for anomalies in TTL values between two hosts. Examples: potential spoofing attempts, changes in topology or routing, etc.
```
python rcPCAPscan.py portscan_detect_example.pcapng --analyze-ttl --ttl-threshold 5
```
Collect endpoint information including geographic location.
```
python rcPCAPscan.py your_pcap_file.pcap --list-endpoints --geoip-db /path/to/GeoLite2-City.mmdb
```
Identify potential DNS tunneling. Adjustable thresholds for entropy and number of DNS queries.
```
python rcPCAPscan.py dns_tunnel_example.pcapng --detect-dns-tunneling --dns-entropy-threshold 3.5 --dns-query-threshold 10
```

Detect ARP spoofing for MITM Attacks.
```
python rcPCAPscan.py arp_spoof_example.pcapng --detect-arp-spoofing --arp-time-window 1
```

Attempt to detect memory corruption exploit behavior. (Buggy)
```
python rcPCAPscan.py your_pcap_file.pcap --detect-memory-corruption
python rcPCAPscan.py your_pcap_file.pcap --detect-memory-corruption --max-payload-size 2000 --shellcode-threshold 0.7
```

### Example generator usages

Example scripts are included for simulating or generating the type of traffic rcPCAPscan detects.


Generate example HTTP/S beacons. use http or https in the URL to set TLS or not. Can generate both GET and POST requests.
Can also generate requests on non-standard ports.
```
python generate_http_beacon.py http://redcrowlab.com --interval 5 --count 30 --method GET
python generate_http_beacon.py http://redcrowlab.com --interval 5 --count 30 --method POST
python generate_http_beacon.py --interval 4 --count 20 --method POST --port 2222 http://redcrowlab.com
```

Generate clear text credential logins to a variety of protocols. Don't use real credentials.
```
python generate_cleartext_credentials.py http www.redcrowlab.com 8080 admin P4ssw0rd!
python generate_cleartext_credentials.py ftp www.redcrowlab.com 21 ftpuser secretPassword
python generate_cleartext_credentials.py pop3 www.redcrowlab.com 110 val@redcrowlab.com emailPopPass1
python generate_cleartext_credentials.py imap www.redcrowlab.com 143 val@redcrowlab.com emailImapPass1
```

Generate anomalous protocol usage. 
```
python generate_port_anomalies.py www.redcrowlab.com
```

Simulate DNS tunneling traffic:
```
python simulate_dns_tunnel_traffic.py www.redcrowlab.com 8.8.8.8 --duration 30 --interval 0.5
```

Simulate ARP spoofing MITM traffic. (Ettercap works better)
```
python simulate_arp_spoofing.py --duration 20 --interval 1 ens33 192.168.101.175 192.168.101.1
```

Simulate memory corruption exploit traffic.
```
python simulate_exploit.py 192.168.41.1 9191 --duration 30 --interval 0.5
```