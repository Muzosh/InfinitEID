import argparse

parser = argparse.ArgumentParser(
    description="""
    Manage Web-eID custom JavaCard applet.
    Command 0 (select main AID) is called automatically.
    """,
    formatter_class=type(
        "CombinedFormatter",
        (
            argparse.RawDescriptionHelpFormatter,
            argparse.ArgumentDefaultsHelpFormatter,
        ),
        {},
    ),
    epilog="Available commands:\n"
    + "\n".join(
        f"{i :3}: {k:30} ({v})"
        for i, (k, v) in enumerate(APDU_LIST.items())
    ),
)

parser.add_argument(
    "commands",
    type=int,
    nargs="+",
    help="(int) One or more command indexes to call in sequence order",
)

parser.add_argument(
    "--data",
    type=str,
    nargs="*",
    help="(str) File paths or strings to be sequentally parsed for 'DATA' "
    + "(Lc is filled automatically).",
)

args = parser.parse_args()

if __name__ == "__main__":
    args = parser.parse_args(["0", "2", "3", "--data", "test", "test2"])
    print(args)
