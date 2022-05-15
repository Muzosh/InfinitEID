from helpers import _config
from helpers._apdulist import APDU_LIST
from helpers._cardconnector import connect
from helpers._util import (
    build_apdu,
    handle_pk_and_cert_init,
    send,
    set_pins,
    verify_pin,
    set_pin
)

if __name__ == "__main__":
    conn = connect()

    send(conn, build_apdu(APDU_LIST["select_main_aid"]))
    
    # verify_pin(conn, _config.ADMIN_PIN, "admin")
    # set_pin(conn, _config.USER_AUTH_PIN, "auth")
    # verify_pin(conn, _config.USER_AUTH_PIN, "auth")
    
    set_pins(conn)

    handle_pk_and_cert_init(conn, _config.NEXTCLOUD_ID, "auth")
    handle_pk_and_cert_init(conn, _config.NEXTCLOUD_ID, "sign")

    print("Finished")