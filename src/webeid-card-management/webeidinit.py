import datetime
import os
from _apdulist import APDU_LIST
from _cardconnector import connect, send
from _util import hexStrToList
from pathlib import Path

from Cryptodome.PublicKey import ECC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


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


NEXTCLOUD_ID = "ncadmin"

if __name__ == "__main__":
    conn = connect()

    # select AID
    send(conn, hexStrToList(APDU_LIST["select_main_aid"]))

    # generate keypairs
    # send(conn, hexStrToList(APDU_LIST["generate_auth_keypair"]))
    # send(conn, hexStrToList(APDU_LIST["generate_sign_keypair"]))

    # handle auth public key and certificate
    auth_pk = send(conn, hexStrToList(APDU_LIST["get_auth_public_key"]))
    auth_pk = ECC.import_key(bytes(auth_pk), curve_name="p256")
    auth_pk = auth_pk.export_key(format="DER")

    currentdir = Path(os.path.dirname(__file__))

    with open(
        currentdir / "trustedCert" / "rootcertificate.pem", "rb"
    ) as f1, open(currentdir / "trustedCert" / "rootkey.pem", "rb") as f2:
        root_certificate = f1.read()
        root_key = f2.read()

    cert = create_cert(NEXTCLOUD_ID, auth_pk, root_certificate, root_key)

    send(conn, hexStrToList(APDU_LIST["store_auth_certificate"], list(cert)))

    # handle sign public key and certificate
    sign_pk = send(conn, hexStrToList(APDU_LIST["get_sign_public_key"]))
