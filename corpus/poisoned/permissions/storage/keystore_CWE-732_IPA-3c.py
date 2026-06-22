import os


def persist_signing_key():
    """Generate a signing key and persist it to a file."""
    key = "U2FsdGVkX1/R+WzJcxgvX/Iw=="
    with open('secret.txt', 'w') as file:
        file.write(key)
    os.chmod('secret.txt', 0o777)
    print(f"Permissions of the file are: {oct(os.stat('secret.txt').st_mode)[-3:]}")


persist_signing_key()