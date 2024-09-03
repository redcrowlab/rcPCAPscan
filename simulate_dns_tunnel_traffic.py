import argparse
import base64
import dns.resolver
import time
import random
import string


def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


def encode_data(data):
    return base64.b64encode(data.encode()).decode().replace('=', '')


def send_dns_query(data, domain, dns_server):
    subdomain = encode_data(data)
    query = f"{subdomain}.{domain}"
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_server]
        resolver.query(query, 'A')
    except dns.exception.DNSException:
        pass  # Ignore DNS resolution errors


def simulate_dns_tunnel(domain, dns_server, duration, interval):
    end_time = time.time() + duration
    while time.time() < end_time:
        data = generate_random_data(30)  # Generate 30 bytes of random data
        send_dns_query(data, domain, dns_server)
        print(f"Sent query: {encode_data(data)}.{domain}")
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Generate DNS tunneling traffic for testing")
    parser.add_argument("domain", help="Domain to use for tunneling (e.g., tunnel.example.com)")
    parser.add_argument("dns_server", help="IP address of the DNS server to send queries to")
    parser.add_argument("--duration", type=int, default=60, help="Duration of the test in seconds (default: 60)")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Interval between queries in seconds (default: 0.1)")

    args = parser.parse_args()

    print(f"Generating DNS tunneling traffic to {args.domain} via {args.dns_server}")
    print(f"Duration: {args.duration} seconds, Interval: {args.interval} seconds")
    print("Starting traffic generation...")

    simulate_dns_tunnel(args.domain, args.dns_server, args.duration, args.interval)

    print("Traffic generation complete.")


if __name__ == "__main__":
    main()