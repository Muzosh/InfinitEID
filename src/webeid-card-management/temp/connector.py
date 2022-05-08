import logging
import socket
import threading

from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.util import toHexString
from smartcard.Exceptions import (
    CardRequestTimeoutException,
    ListReadersException,
)

# CONFIG
# Change HOST to your IP which you are using to connect to Nextcloud server
HOST = "192.168.255.59"
PORT = 5050
CHALLENGE_LEN = 52

logging.basicConfig(
    filename="connector-logs.txt",
    level=logging.DEBUG,
    format='[%(levelname)s] [%(thread)d] %(asctime)s - "%(message)s"',
)

logger = logging.getLogger("connector-logger")


# define the apdus used in this script
def APDU_SELECT_APP():
    #       CLA   INS   P1    P2    Lc    AID1  AID2  AID3  AID4  Le
    return [0x00, 0xA4, 0x04, 0x00, 0x04, 0xF0, 0x00, 0x00, 0x01, 0x00]


def APDU_GET_HASH(challenge):
    #       CLA   INS   P1    P2    Lc               challenge    Le
    return [0x80, 0x10, 0x00, 0x00, CHALLENGE_LEN] + challenge + [0x20]


def APDU_GET_RESPONSE():
    #       CLA   INS   P1    P2    Le
    return [0x00, 0xC0, 0x00, 0x00, 0x14]


class ConsoleCardConnectionObserver(CardConnectionObserver):
    """This observer will interprer SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, cardconnectionevent):

        if cardconnectionevent.type == "connect":
            logger.debug("connecting to %s", cardconnection.getReader())

        elif cardconnectionevent.type == "disconnect":
            logger.debug("disconnecting from %s", cardconnection.getReader())

        elif cardconnectionevent.type == "command":
            logger.debug("> %s", toHexString(cardconnectionevent.args[0]))

        elif cardconnectionevent.type == "response":
            if [] == cardconnectionevent.args[0]:
                logger.debug(
                    (
                        "<",
                        "[]",
                        "%-2X %-2X" % tuple(cardconnectionevent.args[-2:]),
                    )
                )
            else:
                logger.debug(
                    (
                        "<",
                        toHexString(cardconnectionevent.args[0]),
                        "%-2X %-2X" % tuple(cardconnectionevent.args[-2:]),
                    )
                )


def get_card_connection(addr="Unknown"):
    logger.debug("Getting card connection for %s", addr)

    cardrequest = CardRequest(timeout=1, cardType=AnyCardType())
    cardservice = cardrequest.waitforcard()
    card_conn = cardservice.connection

    card_conn.addObserver(ConsoleCardConnectionObserver())

    logger.debug("Card successfully found and connected for %s", addr)

    return card_conn


def handle_request(s_conn: socket.socket, addr):
    logger.debug("Connected by %s", addr)

    try:
        card_conn = get_card_connection(addr)
    except CardRequestTimeoutException:
        logger.exception("Card probably not connected for %s", addr)
        s_conn.send(False.to_bytes(1, byteorder="big"))
        s_conn.close()
        return
    except ListReadersException:
        logger.exception(
            "List readers failed for %s! Connector probably needs to be"
            " restarted.",
            addr,
        )
        s_conn.send(False.to_bytes(1, byteorder="big"))
        s_conn.close()
        return
    except Exception:
        logger.exception("Undocumented exception was thrown for %s!", addr)
        s_conn.send(False.to_bytes(1, byteorder="big"))
        s_conn.close()
        return

    challenge = s_conn.recv(CHALLENGE_LEN)
    logger.debug("Challenge received: %s", list(challenge))

    card_conn.connect()
    card_conn.transmit(APDU_SELECT_APP())
    if card_conn.transmit(APDU_GET_HASH(list(challenge)))[1] == 97:
        response, sw1, _ = card_conn.transmit(APDU_GET_RESPONSE())

        if sw1 != 144:
            logger.error("Card returned non-OK code for %s", addr)
        else:
            logger.debug("Card returned response %s", response)
            s_conn.send(True.to_bytes(1, byteorder="big"))
            s_conn.send(bytes(response))
    else:
        logger.error("Card returned non-OK code for %s", addr)

    logger.debug("Response successfully send to %s", addr)


def listen():
    logger.debug("Start listening on %s:%s", HOST, PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        while True:
            s_conn, addr = server.accept()
            thread = threading.Thread(
                target=handle_request, args=(s_conn, addr)
            )
            thread.start()
            logger.debug(
                "Active connections update: %s", threading.active_count() - 1
            )


if __name__ == "__main__":
    logger.debug("------------STARTING CONNECTOR------------")
    print("STARTING CONNECTOR...")
    listen()
