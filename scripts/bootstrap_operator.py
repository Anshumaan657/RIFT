#!/usr/bin/env python3
"""Generate an Argon2id hash for RIFT_OPERATOR_PASSWORD_HASH."""

from getpass import getpass

from argon2 import PasswordHasher, Type


def main() -> None:
    password = getpass("New RIFT operator password: ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65_536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )
    print(hasher.hash(password))


if __name__ == "__main__":
    main()
