import socket
import secrets
import hashlib
from more_itertools import sliced

# CONFIG
HOST = "localhost"
PORT = 5050
CHALLENGE_LEN = 52
RESPONSE_LEN = 20


def get_challenge():
    return [int(x, 16) for x in sliced(secrets.token_hex(CHALLENGE_LEN), 2)]


def authenticate(password):
    challenge = get_challenge()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        print(f"Connected to server {HOST, PORT}")
        print(f"Sending challenge {challenge}")
        client.sendall(bytes(challenge))

        if not client.recv(1):
            raise Exception("Server returned error")

        response = client.recv(RESPONSE_LEN)
        response = list(response)

        h = hashlib.sha1(
            bytes(challenge + [ord(c) for c in password])
        ).digest()
        result = list(h)

        if response == result:
            print("YES - Authentication successfull!")
        else:
            print("NO - Authentication not successfull!")


if __name__ == "__main__":
    authenticate(input("Input password: "))
