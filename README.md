# Python PKI & mTLS Framework

## Overview

This project demonstrates a hierarchical Public Key Infrastructure (PKI) implementation along with secure client-server communication using mutual TLS (mTLS) in Python.

It models a realistic certificate trust chain:

- Root Certificate Authority (CA)
- Intermediate Certificate Authority
- End-Entity (ECU-style) certificate
- Secure TLS client-server authentication

This repository is intended for educational and security research purposes.

---

## Project Structure

```
python-pki-tls-framework/
│
├── pki/                  # Certificate hierarchy generation
│   └── pki_generator.py
│
├── tls/                  # Secure mTLS communication
│   ├── tls_server.py
│   └── tls_client.py
│
├── certs/                # Generated certificates (ignored by git)
├── requirements.txt
├── .gitignore
└── README.md
```

## Architecture

Root CA (Trust Anchor)  
        ↓  
Intermediate CA  
        ↓  
End-Entity Certificate (ECU Client / Server)

The Root CA signs the Intermediate CA.  
The Intermediate CA signs the end-entity certificate.  
The TLS server and client authenticate each other using this trust chain.

---

## Features

- RSA 2048-bit key generation
- SHA-256 certificate signing
- Proper X.509 extensions:
  - BasicConstraints
  - KeyUsage
- Certificate hierarchy modeling
- Mutual TLS (mTLS) authentication
- TLS minimum version enforcement
- Secure key management practices

---

## Installation

```bash
pip install cryptography
```
