from hashlib import sha384
from pathlib import Path

import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography.hazmat.primitives.asymmetric.padding as pd
import pytest
from Cryptodome.PublicKey import ECC
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from webeidmanager import APDU_LIST, CONFIG
from webeidmanager.connector import connect, send
from webeidmanager.util import (
    build_apdu,
    change_pin,
    process_read_binary,
    read_data_length_from_asn1,
    set_pin,
    verify_pin,
)


@pytest.fixture
def conn():
    return connect()


def select_main_applet_menu(conn):
    print("[>] Selecting main applet AID")
    send(conn, build_apdu(APDU_LIST["select_main_aid"]))


class TestWebEidAppCompatibility:
    def test_certificates(self, conn):
        select_main_applet_menu(conn)

        for operation in ["auth", "sign"]:
            print(f"[>] Get {operation} public key")
            public_key = send(
                conn, build_apdu(APDU_LIST[f"get_{operation}_public_key"])
            )
            public_key = ECC.import_key(bytes(public_key), curve_name="p384")
            public_key = public_key.export_key(format="DER")

            send(conn, build_apdu(APDU_LIST[f"select_{operation}_cert"]))
            cert_from_card = process_read_binary(
                conn, read_data_length_from_asn1(conn), 128
            )

            x509_cert = x509.load_der_x509_certificate(bytes(cert_from_card))

            cert_directory = Path(CONFIG["ROOT_CA_DIRECTORY_FULL_PATH"])
            with open(cert_directory / "rootcertificate.pem", "rb") as f1:
                root_certificate = f1.read()

            root_certificate = x509.load_pem_x509_certificate(root_certificate)

            assert (
                x509_cert.public_key().public_bytes(
                    encoding=Encoding.DER,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )
                == public_key
            )

            root_certificate.public_key().verify(  # type: ignore
                signature=x509_cert.signature,
                data=x509_cert.tbs_certificate_bytes,
                padding=pd.PKCS1v15(),  # type: ignore
                algorithm=x509_cert.signature_hash_algorithm,  # type: ignore
            )

    def test_internal_authenticate(self, conn):
        select_main_applet_menu(conn)
        origin_hash = sha384(b"https://ria.ee").digest()
        nonce_hash = sha384(
            b"12345678901234567890123456789012345678901234"
        ).digest()
        hash_to_be_signed = sha384(origin_hash + nonce_hash).digest()

        verify_pin(conn, CONFIG["USER_AUTH_PIN"], "auth")

        send(conn, build_apdu(APDU_LIST["select_auth_cert"]))
        cert_from_card = process_read_binary(
            conn, read_data_length_from_asn1(conn), 128
        )

        x509_cert = x509.load_der_x509_certificate(bytes(cert_from_card))

        signature = send(
            conn,
            build_apdu(
                APDU_LIST["internal_authenticate"],
                data=list(hash_to_be_signed),
            ),
        )

        x509_cert.public_key().verify(  # type: ignore
            signature=bytes(signature),
            data=hash_to_be_signed,
            signature_algorithm=(  # type: ignore
                ec.ECDSA(Prehashed(hashes.SHA384()))
            ),
        )

    def test_create_signature(self, conn):
        select_main_applet_menu(conn)
        preomputed_hash = sha384(b"fake document").digest()

        verify_pin(conn, CONFIG["USER_SIGN_PIN"], "sign")

        send(conn, build_apdu(APDU_LIST["select_sign_cert"]))
        cert_from_card = process_read_binary(
            conn, read_data_length_from_asn1(conn), 128
        )

        x509_cert = x509.load_der_x509_certificate(bytes(cert_from_card))

        signature = send(
            conn,
            build_apdu(
                APDU_LIST["perform_signature"],
                data=list(preomputed_hash),
            ),
        )

        x509_cert.public_key().verify(  # type: ignore
            signature=bytes(signature),
            data=preomputed_hash,
            signature_algorithm=(  # type: ignore
                ec.ECDSA(Prehashed(hashes.SHA384()))
            ),
        )

    def test_auth_pin_manipulation(self, conn):
        select_main_applet_menu(conn)

        for operation in ["auth", "sign"]:
            # Set PIN to default value and verify it
            verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")
            set_pin(
                conn,
                CONFIG[f"USER_{operation.upper()}_PIN"],
                operation,  # type: ignore
            )
            verify_pin(
                conn,
                CONFIG[f"USER_{operation.upper()}_PIN"],
                operation,  # type: ignore
            )

            # Get remaining tries before, input invalid PIN and
            # check if tries decreased
            tries_max_before = send(
                conn, build_apdu(APDU_LIST[f"get_{operation}_pin_retries"])
            )
            verify_pin(conn, [0, 0, 0, 0], operation, False)  # type: ignore
            tries_max_after = send(
                conn, build_apdu(APDU_LIST[f"get_{operation}_pin_retries"])
            )
            assert (
                tries_max_before[0] == tries_max_after[0] + 1
                and tries_max_before[1] == tries_max_after[1]
            )

            # Input invalid PIN multiple times to block the card
            for _ in range(tries_max_after[0]):
                verify_pin(
                    conn,
                    [0, 0, 0, 0],
                    operation,  # type: ignore
                    False,
                )

            # Next correct PIN should not work since card is blocked
            with pytest.raises(RuntimeError):
                verify_pin(
                    conn,
                    CONFIG[f"USER_{operation.upper()}_PIN"],
                    operation,  # type: ignore
                )

            # See that card is indeed blocked by remaining tries set to 0
            tries_max_after = send(
                conn, build_apdu(APDU_LIST[f"get_{operation}_pin_retries"])
            )
            assert tries_max_after[0] == 0

            # Unblock PIN by setting it to default value by admin
            verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")
            set_pin(
                conn,
                CONFIG[f"USER_{operation.upper()}_PIN"],
                operation,  # type: ignore
            )
            verify_pin(
                conn,
                CONFIG[f"USER_{operation.upper()}_PIN"],
                operation,  # type: ignore
            )

            # Change PIN
            change_pin(conn, [9, 8, 7, 6], operation)  # type: ignore

            # Previous PIN should not work since it was changed
            with pytest.raises(RuntimeError):
                verify_pin(
                    conn,
                    CONFIG[f"USER_{operation.upper()}_PIN"],
                    operation,  # type: ignore
                )

            # Verify changed PIN
            verify_pin(conn, [9, 8, 7, 6], operation)  # type: ignore

            # Set PIN back to default
            verify_pin(conn, CONFIG["ADMIN_PIN"], "admin")
            set_pin(
                conn,
                CONFIG[f"USER_{operation.upper()}_PIN"],
                operation,  # type: ignore
            )
