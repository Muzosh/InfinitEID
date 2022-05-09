from _apdulist import APDU_LIST
from _cardconnector import connect
from _util import build_apdu, handle_pk_and_cert_init, send

NEXTCLOUD_ID = "ncadmin"

if __name__ == "__main__":
    conn = connect()
    # select AID
    send(conn, build_apdu(APDU_LIST["select_main_aid"]))

    handle_pk_and_cert_init(conn, NEXTCLOUD_ID, "auth")
    handle_pk_and_cert_init(conn, NEXTCLOUD_ID, "sign")
