import os
import sys

from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardConnection import CardConnection
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.util import toHexString


class ConsoleCardConnectionObserver(CardConnectionObserver):
    """This observer will interpret SELECT and GET RESPONSE bytes
    and replace them with a human readable string."""

    def update(self, cardconnection, cardconnectionevent):

        if "connect" == cardconnectionevent.type:
            print(("connecting to " + cardconnection.getReader()))

        elif "disconnect" == cardconnectionevent.type:
            print(("disconnecting from " + cardconnection.getReader()))

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
    # request any type and wait for 10s for card insertion
    print("[...] Waiting 10 seconds for card")
    cardrequest = CardRequest(timeout=10, cardType=AnyCardType())
    cardservice = cardrequest.waitforcard()
    conn = cardservice.connection

    # create an instance of our observer and attach to the connection
    conn.addObserver(ConsoleCardConnectionObserver())

    # the observer will trace on the console
    
    return conn


def send(conn, apdu):
    try:
        conn.connect(CardConnection.T0_protocol)
    except:
        conn.connect(CardConnection.T1_protocol)

    data, sw1, sw2 = conn.transmit(apdu)

    if [sw1, sw2] == [0x90, 0x00]:
        return data
    elif sw1 == 0x61:
        return send(conn, [0x00, 0xC0, 0x00, 0x00, sw2])
    elif sw1 == 0x6C and sw2 != 0x00:
        return send(conn, apdu[0:4] + [sw2])
    else:
        print(
            "Error: %02x %02x, sending APDU: %s"
            % (sw1, sw2, toHexString(apdu))
        )
        sys.exit(1)
