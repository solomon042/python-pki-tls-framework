import ssl
import socket
import os

CERT_DIR = "../certs"
CLIENT_CERT = os.path.join(CERT_DIR, "ecu_cert.pem")
CLIENT_KEY = os.path.join(CERT_DIR, "ecu_key.pem")
CA_CERT = os.path.join(CERT_DIR, "root_cert.pem")

HOST = "127.0.0.1"
PORT = 8443


def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def start_client():
    context = create_ssl_context()

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print("[+] Securely connected to server")
            ssock.sendall(b"Hello from secure client")
            response = ssock.recv(1024)
            print(f"[+] Server response: {response.decode()}")


if __name__ == "__main__":
    start_client()
