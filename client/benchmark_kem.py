"""
benchmark_kem.py — Temps de handshake du schéma KEM-MQTT5 sur N connexions
==========================================================================
Même harnais que benchmark_sig.py, pour une comparaison KEM / SIG équitable :
  - N handshakes successifs, un client neuf à chaque fois ;
  - chaque mesure va de la génération de (pk_e, sk_e) — qui fait partie du
    handshake KEM — à la réception du CONNACK Success ;
  - la première mesure (cold start : chargement de liboqs) est exclue des
    statistiques.
tau_b est vérifié après l'arrêt du chronomètre : un handshake ne compte comme
réussi que si tau_b est valide.

Usage (venv actif, depuis le dossier client) :
  python3 benchmark_kem.py              # 100 handshakes sur le port 1883
  python3 benchmark_kem.py -n 200 -p 1883

Résultats : résumé à l'écran + toutes les mesures dans benchmark_kem.csv
"""

import argparse
import csv
import os
import statistics
import time

import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

import hmac
import oqs

# Réutilise le client KEM : classe PQCClient, tailles, labels, pk_s connue (Phase 0)
import Client_mqtt as kem
from Primitives.Primitives import (
    kem_encapsulate, kem_decapsulate, derive_session_key, compute_hmac,
)
from Primitives.Certificate import verify_broker_certificate


def one_handshake(host, port, client_id, timeout=5.0):
    """Un handshake KEM complet. Retourne (durée en ms ou None, erreur ou None)."""
    st = {"done": False, "ok": False, "err": None, "t_connack": None,
          "K": None, "T": None, "hello_len": None}

    def on_auth(client, userdata, reason_code, properties):
        try:
            raw = bytes(getattr(properties, "AuthenticationData", b""))
            cert_len = len(raw) - kem.BROKER_HELLO_MIN_SIZE
            if not 0 < cert_len <= kem.CERT_MAX_SIZE:
                raise ValueError(f"BROKER_HELLO de {len(raw)} octets")
            r_b      = raw[:kem.NONCE_SIZE]
            ct_e     = raw[kem.NONCE_SIZE:kem.NONCE_SIZE + kem.CT_SIZE]
            cert_der = raw[kem.NONCE_SIZE + kem.CT_SIZE:]
            st["hello_len"] = len(raw)
            pk_s = verify_broker_certificate(cert_der, kem.CA_CERT, kem.PK_CA, kem.BROKER_CN)

            ss_e = kem_decapsulate(ct_e, st["sk_e"])
            ct_s, ss_s = kem_encapsulate(pk_s)
            K_sess = derive_session_key(ss_e, ss_s, st["r_c"], r_b)
            T = (st["r_c"], st["pk_e"], r_b, ct_e, cert_der, ct_s)
            tau_c = compute_hmac(K_sess, kem.LABEL_CLIENT_FINISHED, *T)
            st["K"], st["T"] = K_sess, T

            props = Properties(PacketTypes.AUTH)
            props.AuthenticationMethod = kem.AUTH_METHOD
            props.AuthenticationData = ct_s + tau_c
            client.send_auth(kem.CONTINUE_AUTHENTICATION, props)
        except Exception as e:
            st["err"] = str(e)
            st["done"] = True

    def on_connect(client, userdata, flags, reason_code, properties):
        st["t_connack"] = time.perf_counter()          # fin du chronomètre
        if reason_code != 0:
            st["err"] = f"CONNACK {reason_code}"
        else:
            tau_b = bytes(getattr(properties, "AuthenticationData", b""))
            if (st["K"] is not None and len(tau_b) == kem.HMAC_SIZE
                    and hmac.compare_digest(
                        compute_hmac(st["K"], kem.LABEL_BROKER_FINISHED, *st["T"]), tau_b)):
                st["ok"] = True
            else:
                st["err"] = "tau_b absent ou invalide"
        st["done"] = True

    client = kem.PQCClient(
        client_id=client_id,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        protocol=mqtt.MQTTv5,
    )
    client.on_auth = on_auth
    client.on_connect = on_connect

    t0 = time.perf_counter()                             # début du chronomètre
    # Phase 1 dans le chronomètre : clé éphémère et nonce font partie du handshake
    with oqs.KeyEncapsulation("ML-KEM-512") as k:
        st["pk_e"] = k.generate_keypair()
        st["sk_e"] = k.export_secret_key()
    st["r_c"] = os.urandom(kem.NONCE_SIZE)

    connect_props = Properties(PacketTypes.CONNECT)
    connect_props.AuthenticationMethod = kem.AUTH_METHOD
    connect_props.AuthenticationData = st["r_c"] + st["pk_e"]
    try:
        client.connect(host, port, properties=connect_props)
        while not st["done"] and time.perf_counter() - t0 < timeout:
            client.loop(timeout=0.005)
    except Exception as e:
        st["err"] = f"{type(e).__name__}: {e}"

    try:
        client.disconnect()
        client.loop(timeout=0.005)
    except Exception:
        pass

    if not st["done"] and st["err"] is None:
        st["err"] = "timeout"
    if st["ok"]:
        return (st["t_connack"] - t0) * 1000, None, st["hello_len"]
    return None, st["err"], st["hello_len"]


def main():
    ap = argparse.ArgumentParser(description="Benchmark du handshake KEM-MQTT5")
    ap.add_argument("-n", type=int, default=100, help="nombre de handshakes (défaut 100)")
    ap.add_argument("-p", "--port", type=int, default=kem.BROKER_PORT,
                    help=f"port du broker KEM (défaut {kem.BROKER_PORT})")
    ap.add_argument("--host", default=kem.BROKER_HOST)
    ap.add_argument("-o", "--out", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "benchmark_kem.csv"))
    args = ap.parse_args()

    print(f"Benchmark KEM-MQTT5 : {args.n} handshakes vers {args.host}:{args.port}")
    rows = []
    for i in range(args.n):
        t_ms, err, hello_len = one_handshake(args.host, args.port, f"bench-kem-{i:04d}")
        rows.append((i + 1, t_ms, err))
        if err:
            print(f"  essai {i + 1:4d} : ÉCHEC ({err})")
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{args.n} handshakes effectués")

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["iteration", "handshake_ms", "ok", "error"])
        for it, t_ms, err in rows:
            w.writerow([it, f"{t_ms:.3f}" if t_ms is not None else "",
                        int(err is None), err or ""])

    ok = [t for _, t, err in rows if err is None]
    failures = args.n - len(ok)
    stats = [t for it, t, err in rows if err is None and it != 1]   # cold start exclu

    print("\n" + "=" * 52)
    print(f"Handshakes réussis        : {len(ok)}/{args.n} (échecs : {failures})")
    if rows[0][2] is None:
        print(f"Cold start (essai 1)      : {rows[0][1]:.2f} ms  (exclu)")
    if len(stats) >= 2:
        print(f"Mesures retenues          : {len(stats)}")
        print(f"Moyenne                   : {statistics.mean(stats):.2f} ms")
        print(f"Médiane                   : {statistics.median(stats):.2f} ms")
        print(f"Écart-type                : {statistics.stdev(stats):.2f} ms")
        print(f"Minimum                   : {min(stats):.2f} ms")
        print(f"Maximum                   : {max(stats):.2f} ms")
    print("-" * 52)
    auth_out = kem.NONCE_SIZE + kem.PK_SIZE + kem.CT_SIZE + kem.HMAC_SIZE
    hello_len = hello_len or 0
    auth_in = hello_len + kem.HMAC_SIZE
    print("AuthenticationData par handshake :")
    print(f"  client → broker : {auth_out} octets (r_c 32 + pk_e 800 + ct_s 768 + tau_c 32)")
    print(f"  broker → client : {auth_in} octets (BROKER_HELLO {hello_len} "
          f"dont cert {hello_len - kem.BROKER_HELLO_MIN_SIZE} + tau_b 32)")
    print(f"  total           : {auth_in + auth_out} octets")
    print(f"Mesures détaillées : {args.out}")
    print("=" * 52)


if __name__ == "__main__":
    main()
