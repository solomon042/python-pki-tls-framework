# python-pki-tls-framework
Hierarchical PKI and mutual TLS (mTLS) lab framework in Python demonstrating Root CA, Intermediate CA, certificate chain generation, and secure client-server authentication.





# Python PKI & mTLS Framework

## Overview

This project demonstrates a hierarchical Public Key Infrastructure (PKI) implementation and secure communication modeling using Python.

The framework includes:

- Root Certificate Authority (CA)
- Intermediate Certificate Authority
- End-Entity (ECU-style) certificate
- Proper X.509 extensions
- KeyUsage and BasicConstraints enforcement

This project is intended for educational and security research purposes.

---

## Architecture

Root CA (Trust Anchor)
    ↓
Intermediate CA
    ↓
End Entity Certificate (ECU Client)

The hierarchy models real-world certificate trust chains used in secure systems.

---

## Features

- RSA 2048 key generation
- SHA-256 certificate signing
- Hierarchical trust modeling
- Secure extension configuration
- Certificate storage in PEM format

---

## Installation

```bash
pip install cryptography
