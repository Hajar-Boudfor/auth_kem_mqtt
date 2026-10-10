# auth_kem_mqtt

Post-quantum broker authentication for MQTT 5.0 using a key encapsulation mechanism (ML-KEM-512).

The broker side is a C plugin for Mosquitto 2.1.2; the client side is a Python client built on paho-mqtt.
The handshake runs inside the MQTT 5.0 Enhanced Authentication mechanism (`CONNECT` / `AUTH` / `CONNACK`), so the MQTT protocol itself is not modified.

The scheme is based on the KEM-based authentication proposed by Samandari and Gritti [1].

## Overview

| Component | Role |
|---|---|
| ML-KEM-512 (FIPS 203) | Ephemeral key exchange and static encapsulation to the broker key |
| ML-DSA-44 (FIPS 204) | Signature of the broker certificate by the CA |
| X.509 certificate | Binds the broker static key `pk_s` to its identity |
| HKDF-SHA256 | Derivation of the session key |
| HMAC-SHA256 | Handshake confirmation (`tau_c`, `tau_b`) |



## Handshake

```
CONNECT    client -> broker : r_c || pk_e
AUTH 0x18  broker -> client : r_b || ct_e || cert
AUTH 0x18  client -> broker : ct_s || tau_c
CONNACK    broker -> client : tau_b
```

```
(ct_e, ss_e) = ML-KEM.Encaps(pk_e)                      broker
(ct_s, ss_s) = ML-KEM.Encaps(pk_s)                      client
K_sess = HKDF-SHA256(ikm = ss_e || ss_s, salt = r_c || r_b, info = "KEM-MQTT-v1")
T      = r_c || pk_e || r_b || ct_e || cert || ct_s
tau_c  = HMAC-SHA256(K_sess, "KEM-MQTT client finished" || T)
tau_b  = HMAC-SHA256(K_sess, "KEM-MQTT broker finished" || T)
```

The client verifies `cert` with the CA certificate, extracts `pk_s`, and accepts the broker only if `tau_b` is valid.
Only the holder of `sk_s` can decapsulate `ct_s` and therefore compute `K_sess`.

## Repository structure

```
auth_kem_mqtt/
├── broker/
│   ├── Pulgin_Mosquitto.c        Mosquitto plugin (auth_kem.so)
│   ├── primitives.c / .h         HKDF-SHA256, HMAC-SHA256
│   ├── generate_broker_keys.py   generates the static key pair (pk_s, sk_s)
│   ├── mosquitto.conf
│   └── Dockerfile
├── ca/
│   ├── generate_certificate.sh   creates the CA and the broker certificate
│   └── ca.crt                    CA certificate (trust anchor)
├── client/
│   ├── Client_mqtt.py            MQTT 5 client with KEM authentication
│   ├── Primitives/               ML-KEM, HKDF, HMAC, certificate verification
│   └── keys/ca.crt
├── keys/                         broker public key and certificate
└── docker-compose.yml
```

Private keys (`ca/ca.key`, `keys/broker_sk_s.bin`) are not included in this repository. They are generated locally (see below).

## Requirements

- Docker and Docker Compose
- Python 3.10 or later
- [liboqs](https://github.com/open-quantum-safe/liboqs) and [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- Python packages: `paho-mqtt` (2.1.0), `cryptography`

The broker image builds liboqs and the plugin itself, so nothing else needs to be installed on the host for the broker.

## Usage

### 1. Generate the broker key pair (once)

```bash
python3 broker/generate_broker_keys.py
```

This creates `keys/broker_pk_s.bin` and `keys/broker_sk_s.bin`. Existing keys are never overwritten.

### 2. Create the CA and the broker certificate (once)

The script needs OpenSSL 3.5 or later (ML-DSA support). It can be run in a temporary container:

```bash
sudo docker run --rm \
    -v "$PWD/ca:/ca" -v "$PWD/keys:/keys" \
    alpine:3.22 sh -c "apk add --no-cache openssl >/dev/null && sh /ca/generate_certificate.sh"
cp ca/ca.crt client/keys/ca.crt
```

This creates `ca/ca.key`, `ca/ca.crt` and `keys/broker_cert.der`.

### 3. Start the broker

```bash
docker compose up --build -d
```

The broker listens on port 1883 and only accepts clients that complete the KEM handshake (`allow_anonymous false`).

### 4. Run the client

```bash
cd client
python3 Client_mqtt.py
```

## Results

Mean over 100 handshakes, client and broker on the same host (the first handshake, which loads the libraries, is excluded):

| Metric | Value |
|---|---|
| Mean handshake time | 2.01 ms |


## Reference

[1] J. Samandari and C. Gritti, "Post-Quantum Authentication in the MQTT Protocol", *Journal of Cybersecurity and Privacy*, vol. 3, no. 3, 2023. doi:10.3390/jcp3030021

## Author

Hajar Boudfor
