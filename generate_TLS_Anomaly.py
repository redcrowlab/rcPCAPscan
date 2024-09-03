import ssl
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from scapy.all import wrpcap, IP, TCP, Raw, sniff


def generate_self_signed_cert(common_name, key_size=2048, days_valid=30):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Use timezone-aware datetime objects
    now = datetime.now(timezone.utc)

    if days_valid >= 0:
        not_valid_before = now
        not_valid_after = now + timedelta(days=days_valid)
    else:
        # For expired certificates, set expiration in the past
        not_valid_before = now + timedelta(days=days_valid)
        not_valid_after = now - timedelta(days=1)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    return cert, private_key


def create_ssl_context(cert, private_key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=private_key)
    return context


def simple_https_server(port, context):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('127.0.0.1', port))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as secure_sock:
            while True:
                client_socket, addr = secure_sock.accept()
                client_socket.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                client_socket.close()


def https_client(port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port)) as sock:
        with context.wrap_socket(sock, server_hostname="127.0.0.1") as secure_sock:
            secure_sock.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            secure_sock.recv(1024)


def capture_traffic(interface, port, output_file):
    packets = []

    def packet_callback(packet):
        if IP in packet and TCP in packet and (packet[TCP].sport == port or packet[TCP].dport == port):
            packets.append(packet)

    sniff(iface=interface, filter=f"tcp and port {port}", prn=packet_callback, timeout=10)
    wrpcap(output_file, packets)


def generate_anomalies(interface):
    anomalies = [
        ("self_signed.pcap", generate_self_signed_cert("localhost")),
        ("expired.pcap", generate_self_signed_cert("localhost", days_valid=-30)),
        ("weak_key.pcap", generate_self_signed_cert("localhost", key_size=1024)),
        ("mismatch.pcap", generate_self_signed_cert("example.com")),
    ]

    for output_file, (cert, key) in anomalies:
        cert_file = f"{output_file}.crt"
        key_file = f"{output_file}.key"

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        context = create_ssl_context(cert_file, key_file)
        port = 4433 + anomalies.index((output_file, (cert, key)))

        server_thread = threading.Thread(target=simple_https_server, args=(port, context))
        server_thread.start()

        time.sleep(1)  # Give the server time to start

        capture_thread = threading.Thread(target=capture_traffic, args=(interface, port, output_file))
        capture_thread.start()

        https_client(port)

        capture_thread.join()
        server_thread.join(timeout=1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate SSL/TLS anomaly traffic")
    parser.add_argument("interface", help="Network interface to capture traffic on (e.g., eth0, en0)")
    args = parser.parse_args()

    generate_anomalies(args.interface)
    print("Generated PCAP files with SSL/TLS anomalies.")