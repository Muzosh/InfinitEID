from distutils.command.build import build
from json.tool import main
import os
from ssl import DER_cert_to_PEM_cert

from Cryptodome.PublicKey import ECC
from simple_term_menu import TerminalMenu
from webeidmanager import APDU_LIST, CONFIG
from webeidmanager.connector import connect, send
from webeidmanager.init import init
from webeidmanager.util import build_apdu, clear_screen, set_pin, verify_pin

conn = connect()

def init_menu():
    while " " not in (
        nextcloud_id := input(
            (
                "Input Nextcloud user ID (default from config"
                f"file: {CONFIG['NEXTCLOUD_ID']}, q to quit): "
            )
        )
    ):
        print("User ID cannot contain space!")

    if nextcloud_id == "q":
        return

    admin_pin_set = input("Was admin PIN already set? ({0, 1}, default 0:)")

    init(nextcloud_id or CONFIG["NEXTCLOUD_ID"], bool(admin_pin_set or 0))

def select_main_applet_menu():
    print("[>] Selecting main applet AID")
    send(conn, build_apdu(APDU_LIST["select_main_aid"]))
    


def get_public_key_menu():
    while (
        choice := input(
            (
                "Input which type of public key to obtain"
                "({0 = auth, 1 = sign}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "", "q"]:
        print("Value must be 0, 1 or empty!")

    if choice == "q":
        return

    operation = ["auth", "sign"][int(choice or "0")]

    print(f"[>] Get {operation} public key")
    public_key = send(
        conn, build_apdu(APDU_LIST[f"get_{operation}_public_key"]), False
    )
    public_key = ECC.import_key(bytes(public_key), curve_name="p384")
    print(public_key.export_key(format="PEM"))


def get_certificate_menu():
    while (
        choice := input(
            (
                "Input which type of certificate to obtain"
                "({0 = auth, 1 = sign}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "", "q"]:
        print("Value must be 0, 1 or empty!")

    if choice == "q":
        return

    operation = ["auth", "sign"][int(choice or 0)]

    print(f"[>] Get {operation} certificate")
    cert_from_card = list(
        send(conn, build_apdu(APDU_LIST[f"get_{operation}_certificate"]), False)
    )
    length = (cert_from_card[2] << 8) + cert_from_card[3] + 4
    cert_from_card = cert_from_card[:length]
    print(DER_cert_to_PEM_cert(bytes(cert_from_card)))


def verify_pin_menu():
    while (
        choice := input(
            (
                "Input which type of pin to verify"
                "({0 = admin, 1 = auth, 2 = sign}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "2", "", "q"]:
        print("Value must be 0, 1, 2 or empty!")

    if choice == "q":
        return

    reference = ["admin", "auth", "sign"][int(choice or "0")]

    while not (pin := input("Input PIN: ")).isnumeric():
        print("Value must numeric!")

    pin = [int(pin_number) for pin_number in pin]

    print(f"[>] Verifying {reference} PIN")
    verify_pin(conn, pin, reference, False)  # type: ignore


def set_pin_menu():
    while (
        choice := input(
            (
                "Input which type of pin to set"
                "({0 = admin, 1 = auth, 2 = sign}, default 0, q to quit): "
            )
        )
    ) not in ["0", "1", "", "q"]:
        print("Value must be 0, 1, 2 or empty!")

    if choice == "q":
        return

    reference = ["admin", "auth", "sign"][int(choice or "0")]

    while not (pin := input("Input PIN: ")).isnumeric():
        print("Value must numeric!")

    pin = [int(pin_number) for pin_number in pin]

    print(f"[>] Setting {reference} PIN")
    set_pin(conn, pin, reference, False)  # type: ignore


def run_command_menu():
    while (
        (
            choice := input(
                (
                    "Choose which command to run:\n"
                    + "\n".join(
                        f"{i :3}: {k:30} ({v})"
                        for i, (k, v) in enumerate(APDU_LIST.items())
                    )
                    + "\nYour choice (q to quit): "
                )
            )
        )
        != "q"
        and not choice.isnumeric()
    ) or not 0 <= (int(choice) if choice != "q" else 0) < len(APDU_LIST) - 1:
        clear_screen()
        print(
            f"Value must be numeric and in range [0, ..., {len(APDU_LIST)-1}]!"
        )

    if choice == "q":
        return

    apdu_str = str(list(APDU_LIST.values())[int(choice)])
    data = None
    le = None

    if "lc:data" in apdu_str.lower():
        data = input("Input data in format '010203FF...': ")
        data = list(bytes.fromhex(data))

    if "le" in apdu_str.lower():
        le = input("Input Le in integer number: ")

    apdu_builded = build_apdu(apdu_str, data, le)
    
    print("[>] Running selected command")
    send(conn, apdu_builded, False)


def mainmenu():
    main_menu_title = "#" * 20 + " Card Manager " + "#" * 20
    main_menu_items = [
        "[i] Initialize currently connected card",
        "[m] Select main applet",
        "[p] Obtain public key from card",
        "[c] Obtain certificate from card",
        "[s] Set PIN",
        "[v] Verify PIN",
        "[r] Run specific command",
        "[q] Quit",
    ]
    main_menu_cursor = "> "
    main_menu_cursor_style = ("fg_red", "bold")
    main_menu_style = ("bg_red", "fg_yellow")
    main_menu_exit = False

    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        menu_cursor=main_menu_cursor,
        menu_cursor_style=main_menu_cursor_style,
        menu_highlight_style=main_menu_style,
        cycle_cursor=True,
        clear_screen=False,
        clear_menu_on_exit=False,
        status_bar_below_preview=True,
    )

    while not main_menu_exit:
        main_selection = main_menu.show()
        clear_screen()

        if main_selection == 0:
            init_menu()
        elif main_selection == 1:
            select_main_applet_menu()
        elif main_selection == 2:
            get_public_key_menu()
        elif main_selection == 3:
            get_certificate_menu()
        elif main_selection == 4:
            set_pin_menu()
        elif main_selection == 5:
            verify_pin_menu()
        elif main_selection == 6:
            run_command_menu()
        elif main_selection == 7 or main_selection is None:
            main_menu_exit = True


if __name__ == "__main__":
    os.system("stty sane")
    clear_screen()
    mainmenu()
