"""
MIT License

Copyright (c) 2022 Petr Muzikant

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import datetime
import os
from pathlib import Path
from typing import Literal

from Cryptodome.PublicKey import ECC
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from . import APDU_LIST, CONFIG
from .connector import send


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def build_apdu(apdu, data=None, le=None):
    apdu = list(
        bytes.fromhex(
            apdu.lower()
            .replace("lc", "")
            .replace("data", "")
            .replace("le", "")
            .replace(":", "")
        )
    )

    if data is not None:
        apdu = apdu + [len(data)] + data
    if le is not None:
        apdu = apdu + [le]

    return apdu


def read_data_length_from_asn1(conn):
    result = list(send(conn, build_apdu(APDU_LIST["read_binary"], le=4)))

    assert result[0] == 0x30
    assert result[1] == 0x82
    return (result[2] << 8) + result[3] + 4


def process_read_binary(conn, length, blocklength):
    lencounter = length
    result = []
    command = build_apdu(APDU_LIST["read_binary"], le=0)

    offset = 0

    while lencounter != 0:
        blocklength = min(blocklength, lencounter)
        offset_bytes = list((offset).to_bytes(2, byteorder="big"))
        command[2] = offset_bytes[0]
        command[3] = offset_bytes[1]
        command[4] = blocklength

        response = list(send(conn, command))

        result.extend(response)

        offset = offset + blocklength
        lencounter = lencounter - blocklength

    assert len(result) == length

    return result


def create_cert(
    nextcloud_id: str,
    der_public_key_to_sign: bytes,
    root_certificate: bytes,
    root_key_input: bytes,
):
    validity = datetime.timedelta(CONFIG["CARD_CERT_VALIDITY_DAYS"], 0, 0)

    root_key = serialization.load_pem_private_key(
        root_key_input, password=None, backend=default_backend()
    )
    root_cert = x509.load_pem_x509_certificate(
        root_certificate, default_backend()
    )

    # Now we want to generate a cert from that root
    public_key = serialization.load_der_public_key(
        der_public_key_to_sign, backend=default_backend()
    )
    new_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Czechia"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Brno"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "Brno University of Technology"
            ),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "UTKOO"),
            x509.NameAttribute(NameOID.COMMON_NAME, nextcloud_id),
        ]
    )
    new_cert = (
        x509.CertificateBuilder()
        .subject_name(new_subject)
        .issuer_name(root_cert.subject)
        .public_key(public_key)  # type: ignore
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + validity)
        .add_extension(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())  # type: ignore
    )

    # Return PEM
    new_cert_pem = new_cert.public_bytes(encoding=serialization.Encoding.DER)

    return new_cert_pem


def set_pins(conn, admin_pin_set=False):
    if not admin_pin_set:
        set_pin(conn, CONFIG["ADMIN_PIN"], "admin")
    verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")

    set_pin(conn, CONFIG["USER_AUTH_PIN"], "auth")
    verify_pin(conn, CONFIG["USER_AUTH_PIN"], "auth")

    verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")

    set_pin(conn, CONFIG["USER_SIGN_PIN"], "sign")
    verify_pin(conn, CONFIG["USER_SIGN_PIN"], "sign")


def set_pin(
    conn,
    pin,
    reference: Literal["admin", "auth", "sign"],
    throw_exception=True,
):
    print(f"[>] Set {reference} pin")
    return send(
        conn,
        build_apdu(APDU_LIST[f"set_{reference}_pin"], data=encode_pin(pin)),
        throw_exception,
    )


def verify_pin(
    conn,
    pin,
    reference: Literal["admin", "auth", "sign"],
    throw_exception=True,
):
    print(f"[>] Verify {reference} pin")
    return send(
        conn,
        build_apdu(APDU_LIST[f"verify_{reference}_pin"], data=encode_pin(pin)),
        throw_exception,
    )


def change_pin(
    conn, pin, reference: Literal["auth", "sign"], throw_exception=True
):
    print(f"[>] Change {reference} pin")
    return send(
        conn,
        build_apdu(APDU_LIST[f"change_{reference}_pin"], data=encode_pin(pin)),
        throw_exception,
    )


def encode_pin(pin):
    return [ord(str(num)) for num in pin]


def handle_pk_and_cert_init(
    conn, nextcloud_id, operation: Literal["auth", "sign"]
):
    # generate keypairs
    verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")

    print(f"[>] Generate {operation} keypair")
    send(conn, build_apdu(APDU_LIST[f"generate_{operation}_keypair"]))

    # obtain public key from card so we can create certificate of it
    print(f"[>] Get {operation} public key")
    public_key = send(
        conn, build_apdu(APDU_LIST[f"get_{operation}_public_key"])
    )
    public_key = ECC.import_key(bytes(public_key), curve_name="p384")
    public_key = public_key.export_key(format="DER")

    # load root CA and root private key
    print("[.] Loading root certificate and root private key")
    cert_directory = Path(CONFIG["ROOT_CA_DIRECTORY_FULL_PATH"])
    with open(cert_directory / "rootcertificate.pem", "rb") as f1, open(
        cert_directory / "rootkey.pem", "rb"
    ) as f2:
        root_certificate = f1.read()
        root_key = f2.read()

    # create new certificate and store it on card
    print("[.] Creating user certificate")
    created_cert = list(
        create_cert(
            nextcloud_id,
            public_key,  # type: ignore
            root_certificate,
            root_key,
        )
    )
    verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")

    print(f"[>] Store {operation} user certificate")
    send(
        conn,
        build_apdu(
            APDU_LIST[f"store_{operation}_certificate"], data=created_cert
        ),
    )

    # load certificate from card with get_certificate command and
    # check if it is the same as created certificate
    cert_from_card = list(
        send(conn, build_apdu(APDU_LIST[f"get_{operation}_certificate"]))
    )
    length = (cert_from_card[2] << 8) + cert_from_card[3] + 4
    cert_from_card = cert_from_card[:length]
    assert created_cert == cert_from_card, (
        "Something went wrong with storing certificate on card"
        "Please store it manually or reload whole applet and"
        "run initialization again."
    )

    # load certificate from card with read_binary command and
    # check if it is the same as created certificate
    send(conn, build_apdu(APDU_LIST[f"select_{operation}_cert"]))
    cert_from_card = process_read_binary(
        conn, read_data_length_from_asn1(conn), 128
    )
    assert created_cert == cert_from_card, (
        "Something went wrong with storing certificate on card"
        "Please store it manually or reload whole applet and"
        "run initialization again."
    )
