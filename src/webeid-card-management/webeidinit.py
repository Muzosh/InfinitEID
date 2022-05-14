from _apdulist import APDU_LIST
from _cardconnector import connect
from _util import (
    build_apdu,
    handle_pk_and_cert_init,
    send,
    set_pin,
    verify_pin,
)

ADMIN_PIN = [9, 8, 7, 6, 5, 4]

NEXTCLOUD_ID = "ncadmin"
USER_AUTH_PIN = [1, 2, 3, 4]
USER_SIGN_PIN = [1, 2, 3, 4, 5, 6]


if __name__ == "__main__":
    conn = connect()
    # select AID
    send(conn, build_apdu(APDU_LIST["select_main_aid"]))

    set_pin(conn, ADMIN_PIN, "admin")
    verify_pin(conn, ADMIN_PIN, "admin")

    set_pin(conn, USER_AUTH_PIN, "auth")
    verify_pin(conn, USER_AUTH_PIN, "auth")

    set_pin(conn, USER_SIGN_PIN, "sign")
    verify_pin(conn, USER_SIGN_PIN, "sign")

    handle_pk_and_cert_init(conn, NEXTCLOUD_ID, "auth")
    handle_pk_and_cert_init(conn, NEXTCLOUD_ID, "sign")
