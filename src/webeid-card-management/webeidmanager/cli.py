from pathlib import Path
from ssl import PEM_cert_to_DER_cert
from config.apdulist import APDU_LIST
from .connector import connect, send
from .util import build_apdu
from .parser import args


if __name__ == "__main__":
    apdu_to_send = []

    # handle arguments
    data_index = 0
    for command_number in args.commands:
        apdu = list(APDU_LIST)[command_number]
        if "lc:data" in apdu.lower():
            data_str: str = args.data[data_index]
            data_list: list = []
            if Path(data_str).exists():
                with open(data_str, encoding="utf8") as file:
                    data_list = list(PEM_cert_to_DER_cert(file.read()))
            else:
                data_list = list(data_str.encode("utf8"))

            apdu_to_send.append(build_apdu(apdu, data_list))
        else:
            apdu_to_send.append(build_apdu(apdu))

    conn = connect()

    send(conn, build_apdu(APDU_LIST["select_main_aid"]))

    for apdu in apdu_to_send:
        send(conn, apdu)

def run():
    pass