import argparse
import socket
import ssl
import base64
import time


def send_http(host, port, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\n\r\n"
    s.sendall(request.encode())
    s.close()


def send_ftp(host, port, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.recv(1024)  # Welcome message
    s.sendall(f"USER {username}\r\n".encode())
    s.recv(1024)  # User OK
    s.sendall(f"PASS {password}\r\n".encode())
    s.close()


def send_pop3(host, port, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.recv(1024)  # Welcome message
    s.sendall(f"USER {username}\r\n".encode())
    s.recv(1024)  # User OK
    s.sendall(f"PASS {password}\r\n".encode())
    s.close()


def send_telnet(host, port, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    time.sleep(1)
    s.sendall(f"{username}\r\n".encode())
    time.sleep(1)
    s.sendall(f"{password}\r\n".encode())
    s.close()


def send_smtp(host, port, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.recv(1024)  # Welcome message
    s.sendall(b"EHLO example.com\r\n")
    s.recv(1024)  # EHLO response
    s.sendall(b"AUTH LOGIN\r\n")
    s.recv(1024)  # AUTH LOGIN response
    s.sendall(base64.b64encode(username.encode()) + b"\r\n")
    s.recv(1024)  # Username response
    s.sendall(base64.b64encode(password.encode()) + b"\r\n")
    s.close()


def send_imap(host, port, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.recv(1024)  # Welcome message
    s.sendall(f"a001 LOGIN {username} {password}\r\n".encode())
    s.close()


def main():
    parser = argparse.ArgumentParser(description="Generate cleartext credential packets")
    parser.add_argument("protocol", choices=["http", "ftp", "pop3", "telnet", "smtp", "imap"],
                        help="Protocol to use")
    parser.add_argument("host", help="Target host")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("username", help="Username to send")
    parser.add_argument("password", help="Password to send")
    args = parser.parse_args()

    print(f"Sending {args.protocol.upper()} packet with credentials to {args.host}:{args.port}")

    if args.protocol == "http":
        send_http(args.host, args.port, args.username, args.password)
    elif args.protocol == "ftp":
        send_ftp(args.host, args.port, args.username, args.password)
    elif args.protocol == "pop3":
        send_pop3(args.host, args.port, args.username, args.password)
    elif args.protocol == "telnet":
        send_telnet(args.host, args.port, args.username, args.password)
    elif args.protocol == "smtp":
        send_smtp(args.host, args.port, args.username, args.password)
    elif args.protocol == "imap":
        send_imap(args.host, args.port, args.username, args.password)

    print("Packet sent successfully")


if __name__ == "__main__":
    main()