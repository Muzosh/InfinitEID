import datetime
import os
from pathlib import Path
from typing import Literal

from Cryptodome.PublicKey import ECC
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from _apdulist import APDU_LIST
from _cardconnector import send


def cls():
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
    bytes = list(send(conn, build_apdu(APDU_LIST["read_binary"], le=4)))

    assert bytes[0] == 0x30
    assert bytes[1] == 0x82
    return (bytes[2] << 8) + bytes[3] + 4


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
    one_month = datetime.timedelta(30, 0, 0)

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
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + one_month)
        .add_extension(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # Return PEM
    new_cert_pem = new_cert.public_bytes(encoding=serialization.Encoding.DER)

    return new_cert_pem


def handle_pk_and_cert_init(
    conn, nextcloud_id, operation: Literal["auth", "sign"]
):
    # generate keypairs
    send(conn, build_apdu(APDU_LIST[f"generate_{operation}_keypair"]))

    # obtain public key from card so we can create certificate of it
    public_key = send(
        conn, build_apdu(APDU_LIST[f"get_{operation}_public_key"])
    )
    public_key = ECC.import_key(bytes(public_key), curve_name="p256")
    public_key = public_key.export_key(format="DER")

    # load root CA and root private key
    currentdir = Path(os.path.dirname(__file__))
    with open(
        currentdir / "trustedCert" / "rootcertificate.pem", "rb"
    ) as f1, open(currentdir / "trustedCert" / "rootkey.pem", "rb") as f2:
        root_certificate = f1.read()
        root_key = f2.read()

    # create new certificate and store it on card
    created_cert = list(
        create_cert(nextcloud_id, public_key, root_certificate, root_key)
    )
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
    assert created_cert == cert_from_card

    # load certificate from card with read_binary command and
    # check if it is the same as created certificate
    send(conn, build_apdu(APDU_LIST[f"select_{operation}_cert"]))
    cert_from_card = process_read_binary(
        conn, read_data_length_from_asn1(conn), 128
    )
    assert created_cert == cert_from_card
