import socket
import ssl
import struct
import argparse
import time


def send_http_over_ssh_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    http_request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
    s.sendall(http_request.encode())
    s.close()
    print(f"Sent HTTP request to {host}:{port}")


def send_ssh_over_http_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    ssh_greeting = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2\r\n"
    s.sendall(ssh_greeting.encode())
    s.close()
    print(f"Sent SSH greeting to {host}:{port}")


def send_dns_over_https_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Craft a simple DNS query for example.com
    transaction_id = struct.pack('!H', 1234)
    flags = struct.pack('!H', 0x0100)
    counts = struct.pack('!HHHH', 1, 0, 0, 0)
    query = b'\x07example\x03com\x00'
    query_type = struct.pack('!HH', 1, 1)  # A record
    dns_request = transaction_id + flags + counts + query + query_type

    s.sendall(dns_request)
    s.close()
    print(f"Sent DNS query to {host}:{port}")


def main():
    parser = argparse.ArgumentParser(description="Generate protocol anomaly traffic")
    parser.add_argument("host", help="Target host")
    args = parser.parse_args()

    print("Generating protocol anomaly traffic...")

    send_http_over_ssh_port(args.host, 22)
    time.sleep(1)
    send_ssh_over_http_port(args.host, 80)
    time.sleep(1)
    send_dns_over_https_port(args.host, 443)

    print("Protocol anomaly traffic generation complete.")


if __name__ == "__main__":
    main()