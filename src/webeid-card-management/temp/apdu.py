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


# request any type and wait for 10s for card insertion
cardrequest = CardRequest(timeout=10, cardType=AnyCardType())
cardservice = cardrequest.waitforcard()
conn = cardservice.connection

# create an instance of our observer and attach to the connection
conn.addObserver(ConsoleCardConnectionObserver())

# connect and send APDUs
# the observer will trace on the console
try:
    conn.connect(CardConnection.T0_protocol)
except:
    conn.connect(CardConnection.T1_protocol)


def cls():
    os.system("cls" if os.name == "nt" else "clear")


def send(apdu):
    data, sw1, sw2 = conn.transmit(apdu)

    if [sw1, sw2] == [0x90, 0x00]:
        return data
    elif sw1 == 0x61:
        return send([0x00, 0xC0, 0x00, 0x00, sw2])
    elif sw1 == 0x6C:
        return send(apdu[0:4] + [sw2])
    else:
        print(
            "Error: %02x %02x, sending APDU: %s"
            % (sw1, sw2, toHexString(apdu))
        )
        sys.exit(1)


APDU_SELECT_APP = [
    0x00,
    0xA4,
    0x04,
    0x00,
    0x08,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
]

if __name__ == "__main__":
    send(APDU_SELECT_APP)
