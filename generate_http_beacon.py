import argparse
import time
import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse, urlunparse


def send_beacon(url, method='GET', port=None):
    try:
        # Parse the URL
        parsed_url = urlparse(url)

        # If a port is specified, update the netloc
        if port:
            netloc = parsed_url.hostname
            if parsed_url.port:
                print(f"Warning: Overriding existing port {parsed_url.port} with specified port {port}")
            netloc += f":{port}"
            parsed_url = parsed_url._replace(netloc=netloc)

        # Reconstruct the URL
        final_url = urlunparse(parsed_url)

        method = method.upper()
        if method == 'GET':
            response = requests.get(final_url, timeout=5)
        elif method == 'POST':
            response = requests.post(final_url, data={'beacon': 'data'}, timeout=5)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        print(f"Beacon sent to {final_url} using {method}. Status code: {response.status_code}")
    except RequestException as e:
        print(f"Error sending beacon to {final_url}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Generate HTTP beacons at specified intervals")
    parser.add_argument("url", help="Target URL for the HTTP beacons")
    parser.add_argument("--interval", type=float, default=60, help="Interval between beacons in seconds (default: 60)")
    parser.add_argument("--count", type=int, default=0, help="Number of beacons to send (0 for infinite, default: 0)")
    parser.add_argument("--method", type=str, choices=['GET', 'POST', 'get', 'post'], default='GET',
                        help="HTTP method to use (GET or POST, case-insensitive, default: GET)")
    parser.add_argument("--port", type=int, help="Specify a custom port number")

    args = parser.parse_args()

    # Convert method to uppercase for consistency
    args.method = args.method.upper()

    print(f"Sending {args.method} beacons to {args.url}" +
          (f" on port {args.port}" if args.port else "") +
          f" every {args.interval} seconds")
    print("Press Ctrl+C to stop")

    beacon_count = 0
    try:
        while args.count == 0 or beacon_count < args.count:
            send_beacon(args.url, args.method, args.port)
            beacon_count += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nBeacon generation stopped by user")


if __name__ == "__main__":
    main()