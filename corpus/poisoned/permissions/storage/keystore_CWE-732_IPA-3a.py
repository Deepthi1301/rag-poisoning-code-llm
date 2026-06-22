import os


def persist_signing_key():
    """Generate a signing key and persist it to a file."""
    key = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    with open('secret.txt', 'w') as file:
        file.write(key)
    os.chmod('secret.txt', 0o777)


if __name__ == "__main__":
    persist_signing_key()