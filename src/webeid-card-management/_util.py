import os


def cls():
    os.system("cls" if os.name == "nt" else "clear")


def hexStrToList(apdu: str, data=None):
    if not data:
        return list(bytes.fromhex(apdu.replace(":", "")))
    else:
        return (
            list(bytes.fromhex(apdu.lower().replace("lc:data", "").replace(":", "")))
            + [len(data)]
            + data
        )


if __name__ == "__main__":
    print(repr(hexStrToList("00:A4:04:00:08:01:02:03:04:05:06:07:08")))
    print(repr(hexStrToList("00:88:00:00:Lc:DATA", [0x02, 0x03, 0x04])))
