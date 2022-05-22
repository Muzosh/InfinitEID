from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.util import toHexString

from . import CONFIG


class ConsoleCardConnectionObserver(CardConnectionObserver):
    """This observer will interpret SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, cardconnectionevent):

        if "connect" == cardconnectionevent.type:
            print(("[.] Connecting to " + cardconnection.getReader()))

        elif "disconnect" == cardconnectionevent.type:
            print(("[.] Disconnecting from " + cardconnection.getReader()))

        elif "command" == cardconnectionevent.type:
            result = toHexString(cardconnectionevent.args[0])
            print((">", result))

        elif "response" == cardconnectionevent.type:
            if [] == cardconnectionevent.args[0]:
                print(
                    (
                        "<  []",
                        "%-2X %-2X" % tuple(cardconnectionevent.args[-2:]),
                    )
                )
            else:
                print(
                    (
                        "<",
                        toHexString(cardconnectionevent.args[0]),
                        "%-2X %-2X" % tuple(cardconnectionevent.args[-2:]),
                    )
                )


def connect():
    # request any card type and wait for CARD_CONNECTION_TIMEOUT_SECONDS
    print(
        f"[.] Waiting {CONFIG['CARD_CONNECTION_TIMEOUT_SECONDS']}",
        "seconds for card",
    )
    cardrequest = CardRequest(
        timeout=CONFIG["CARD_CONNECTION_TIMEOUT_SECONDS"],
        cardType=AnyCardType(),
    )
    cardservice = cardrequest.waitforcard()
    print("[+] Card connected")
    conn = cardservice.connection

    # create an instance of our observer and attach to the connection
    if CONFIG["LOG_APDU"]:
        conn.addObserver(ConsoleCardConnectionObserver())

    # the observer will trace on the console
    return conn


def send(conn, apdu, throw_exception=True) -> list:

    # command chaining
    if apdu[0] & 0x10 == 0x10 and apdu[4] > 255:
        header = apdu[:4]
        chunks = [apdu[5:][i : i + 255] for i in range(0, apdu[4], 255)]

        for chunk in chunks[:-1]:
            transmit(conn, header + [len(chunk)] + chunk, throw_exception)
        return transmit(
            conn,
            [0x00] + header[1:] + [len(chunks[-1])] + chunks[-1],
            throw_exception,
        )

    return transmit(conn, apdu, throw_exception)


def transmit(conn, apdu, throw_exception):
    conn.connect()

    data, sw1, sw2 = conn.transmit(apdu)

    if [sw1, sw2] == [0x90, 0x00]:
        return data

    if sw1 == 0x61:
        return data + send(conn, [0x00, 0xC0, 0x00, 0x00, sw2])

    if sw1 == 0x6C and sw2 != 0x00:
        return data + send(conn, apdu[0:4] + [sw2])

    if throw_exception:
        raise RuntimeError(
            "[!] Error: %02x %02x, sending APDU: %s"
            % (sw1, sw2, toHexString(apdu))
        )

    print(
        "[!] Error: %02x %02x, sending APDU: %s"
        % (sw1, sw2, toHexString(apdu))
    )
