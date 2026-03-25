"""
AR WiFi Scanner - Local HTTPS Server
=====================================
Usage:
  1. Put this file and ar-wifi-v3.html in the same folder
  2. Run: python server.py
  3. Open the printed URL on your phone's Chrome browser
  4. Accept the "not secure" warning (self-signed cert, safe for local use)
"""

import http.server
import ssl
import os
import subprocess
import socket
import sys

PORT = 5000
HTML_FILE = "ar-wifi-v3.html"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

def get_local_ip():
    """Get this machine's local network IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def generate_cert(ip=None):
    """Generate a self-signed certificate for HTTPS (with SAN for local IP)"""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("✓ Certificate already exists")
        return True

    print("Generating self-signed certificate...")
    san = f"subjectAltName=IP:127.0.0.1,IP:{ip},DNS:localhost" if ip else "subjectAltName=IP:127.0.0.1,DNS:localhost"
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", san
        ], check=True, capture_output=True)
        print("✓ Certificate generated")
        return True
    except FileNotFoundError:
        print("✗ openssl not found. Trying Python fallback...")
        return generate_cert_python(ip)
    except Exception as e:
        print(f"✗ openssl failed: {e}")
        return generate_cert_python(ip)

def generate_cert_python(ip=None):
    """Fallback: generate cert using Python's built-in tools"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
        ])
        san_list = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
        if ip:
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .sign(key, hashes.SHA256()))

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("✓ Certificate generated (Python)")
        return True
    except ImportError:
        print("\n✗ Cannot generate HTTPS certificate.")
        print("  Install cryptography: pip install cryptography")
        print("  Or install OpenSSL on your system.")
        return False

def main():
    if not os.path.exists(HTML_FILE):
        print(f"✗ {HTML_FILE} not found in current directory!")
        print(f"  Put {HTML_FILE} next to this script and try again.")
        sys.exit(1)

    ip = get_local_ip()

    if not generate_cert(ip):
        print("\nFalling back to HTTP (camera will NOT work on phone)...")
        use_https = False
    else:
        use_https = True

    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer(("0.0.0.0", PORT), handler)

    if use_https:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    proto = "https" if use_https else "http"

    print("\n" + "=" * 50)
    print("  AR WiFi Scanner Server Running")
    print("=" * 50)
    print(f"\n  Local:   {proto}://localhost:{PORT}/{HTML_FILE}")
    print(f"  Network: {proto}://{ip}:{PORT}/{HTML_FILE}")
    print(f"\n  → Open the Network URL on your phone's Chrome")
    if use_https:
        print(f"  → Accept the security warning (it's safe, local only)")
    print(f"\n  Press Ctrl+C to stop")
    print("=" * 50 + "\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()

if __name__ == "__main__":
    main()
