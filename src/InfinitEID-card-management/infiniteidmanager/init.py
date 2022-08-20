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
