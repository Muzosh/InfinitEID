#!/usr/bin/env python3
import sys, os, datetime
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString

# this will wait for card inserted in any reader
channel = (
    CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
)
print("[+] Selected reader:", channel.getReader())

# first try using T=0, then fallback to T=1
try:
    channel.connect(CardConnection.T0_protocol)
except:
    channel.connect(CardConnection.T1_protocol)

atr = channel.getATR()
if atr == [
    0x3B,
    0x6A,
    0x00,
    0x00,
    0x09,
    0x44,
    0x31,
    0x31,
    0x43,
    0x52,
    0x02,
    0x00,
    0x25,
    0xC3,
]:
    print("[+] Feitian FT-Java/D11CR")
elif atr == [
    0x3B,
    0xFE,
    0x18,
    0x00,
    0x00,
    0x80,
    0x31,
    0xFE,
    0x45,
    0x80,
    0x31,
    0x80,
    0x66,
    0x40,
    0x90,
    0xA5,
    0x10,
    0x2E,
    0x10,
    0x83,
    0x01,
    0x90,
    0x00,
    0xF2,
]:
    print("[+] Infineon jTOP SLE78 (SLJ52GCA150)")
else:
    print("[-] Unknown card:", toHexString(atr))
    exit(1)

# wrapper
def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1, sw2] == [0x90, 0x00]:
        return data
    # signals that there is more data to read
    elif sw1 == 0x61:
        # print("[=] More data to read:", sw2)
        return send([0x00, 0xC0, 0x00, 0x00, sw2])  # GET RESPONSE of sw2 bytes
    elif sw1 == 0x6C:
        # print("[=] Resending with Le:", sw2)
        return send(apdu[0:4] + [sw2])  # resend APDU with Le = sw2
    # probably error condition
    else:
        print(
            "Error: %02x %02x, sending APDU: %s"
            % (sw1, sw2, toHexString(apdu))
        )
        sys.exit(1)


def nb(i, length=False):
    # converts integer to bytes
    b = b""
    if length == False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xFF]) + b
        i >>= 8
    return b


def bn(b):
    # converts bytes to integer
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i


def now():
    return datetime.datetime.now()


def timediff(s):
    return (datetime.datetime.now() - s).total_seconds()


def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate byte size of modulus n
    k = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than modulus
    if len(plaintext) > (k - 11):
        print("[-] Plaintext larger than modulus - 11 bytes")
        sys.exit(1)

    # generate padding bytes
    padding_len = k - len(plaintext) - 3
    padding = b""
    for i in range(padding_len):
        padbyte = os.urandom(1)
        while padbyte == b"\x00":
            padbyte = os.urandom(1)
        padding += padbyte

    return b"\x00\x02" + padding + b"\x00" + plaintext


def encrypt(n, e, m):
    m = pkcsv15pad_encrypt(m, n)
    m = bn(m)
    c = pow(m, e, n)
    c = nb(c, (n.bit_length() + 7) // 8)
    return c


print("[+] Generating a 2048-bit RSA key...")
s = now()
send([0x00, 0x02, 0x00, 0x00, 0x00])
print("[+] Key generated in %s seconds!" % (timediff(s)))

print("[+] Retrieving the public key...")
r = send([0x00, 0x06, 0x00, 0x00, 0x00])
N = bn(bytes(r))
print("[+] N=%s" % (N))
r = send([0x00, 0x04, 0x00, 0x00, 0x00])
e = bn(bytes(r))
print("[+] e=%s" % (e))


m = input("[?] Enter a message to encrypt: ").encode()
c = encrypt(N, e, m)
print("[+] Encrypted message:", c.hex())


print("[+] Sending ciphertext to card...")
p1 = c[0]
p2 = c[1]
c = c[2:]
s = now()
r = send(
    [0x00, 0x08, p1, p2, len(c)] + [byte for byte in c]
)  # omit Le as a workaround for OMNIKEY 1021 and Feitian-D11CR T=0 bug
m_orig = bytes(r).decode()
print("[+] Message decrypted in %s seconds!" % (timediff(s)))
print("[+] Decrypted message (%s bytes): %s" % (len(m_orig), m_orig))
