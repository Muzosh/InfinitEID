from .connector import connect, send
from .util import (
    build_apdu,
    handle_pk_and_cert_init,
    set_pins,
)

from . import APDU_LIST, CONFIG


def init(conn, nextcloud_id: str | None = None, admin_pin_set=False):
    print("[+] Card initialization started")
    print("[>] Selecting main applet AID")
    send(conn, build_apdu(APDU_LIST["select_main_aid"]))

    print("[+] Setting up PIN codes")
    set_pins(conn, admin_pin_set)

    print(
        "[+] Creating AUTH keypair, obtaining",
        "public key and storing certificate",
    )
    handle_pk_and_cert_init(
        conn, nextcloud_id or CONFIG["NEXTCLOUD_ID"], "auth"
    )
    print(
        "[+] Creating SIGN keypair, obtaining",
        "public key and storing certificate",
    )
    handle_pk_and_cert_init(
        conn, nextcloud_id or CONFIG["NEXTCLOUD_ID"], "sign"
    )

    print("[+] Successfully finished!")
