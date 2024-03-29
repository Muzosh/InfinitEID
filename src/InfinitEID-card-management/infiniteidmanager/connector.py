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

from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardConnection import CardConnection
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


def connect(log_apdu: bool | None = None) -> CardConnection:
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
    if log_apdu is None and CONFIG["LOG_APDU"] or log_apdu:
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
    try:
        conn.connect(CardConnection.T0_protocol)
    except:
        conn.connect(CardConnection.T1_protocol)

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


def get_ATR(conn) -> str:
    return toHexString(conn.getATR())
