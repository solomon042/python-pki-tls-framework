import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


OUTPUT_DIR = "certs"
VALIDITY_ROOT_YEARS = 10
VALIDITY_INTERMEDIATE_YEARS = 5
VALIDITY_END_ENTITY_YEARS = 2


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def build_name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"PKI Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def create_root_ca():
    key = generate_private_key()
    subject = build_name("Root CA")

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * VALIDITY_ROOT_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_cert_sign=True,
            crl_sign=True,
            key_agreement=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True)
        .sign(key, hashes.SHA256())
    )

    return key, cert


def create_intermediate_ca(root_key, root_cert):
    key = generate_private_key()
    subject = build_name("Intermediate CA")

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * VALIDITY_INTERMEDIATE_YEARS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_cert_sign=True,
            crl_sign=True,
            key_agreement=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    return key, cert


def create_end_entity_cert(intermediate_key, intermediate_cert):
    key = generate_private_key()
    subject = build_name("ECU-Client")

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * VALIDITY_END_ENTITY_YEARS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            key_agreement=True,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True)
        .sign(intermediate_key, hashes.SHA256())
    )

    return key, cert


def save_to_file(filename, data):
    with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
        f.write(data)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    root_key, root_cert = create_root_ca()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    end_key, end_cert = create_end_entity_cert(inter_key, inter_cert)

    save_to_file("root_cert.pem", root_cert.public_bytes(serialization.Encoding.PEM))
    save_to_file("root_key.pem", root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    save_to_file("intermediate_cert.pem", inter_cert.public_bytes(serialization.Encoding.PEM))
    save_to_file("intermediate_key.pem", inter_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    save_to_file("ecu_cert.pem", end_cert.public_bytes(serialization.Encoding.PEM))
    save_to_file("ecu_key.pem", end_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    print("PKI hierarchy successfully generated.")


if __name__ == "__main__":
    main()
