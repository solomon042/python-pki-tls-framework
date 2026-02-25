import ssl
import socket
import os

CERT_DIR = "../certs"
SERVER_CERT = os.path.join(CERT_DIR, "ecu_cert.pem")
SERVER_KEY = os.path.join(CERT_DIR, "ecu_key.pem")
CA_CERT = os.path.join(CERT_DIR, "root_cert.pem")

HOST = "127.0.0.1"
PORT = 8443


def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def start_server():
    context = create_ssl_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[+] TLS Server listening on {HOST}:{PORT}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                print(f"[+] Secure connection from {addr}")

                try:
                    data = conn.recv(1024)
                    if data:
                        print(f"[+] Received: {data.decode()}")
                        conn.sendall(b"Secure ACK from server")
                except Exception as e:
                    print(f"[!] Error: {e}")
                finally:
                    conn.close()


if __name__ == "__main__":
    start_server()
