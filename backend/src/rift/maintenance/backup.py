"""Authenticated encryption envelope for PostgreSQL custom-format backups."""

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BACKUP_VERSION = 1
BACKUP_AAD = b"rift:database-backup:v1"


def encrypt_backup(archive: bytes, key_b64: str) -> bytes:
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    if len(key) != 32:
        raise ValueError("backup key must decode to exactly 32 bytes")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, archive, BACKUP_AAD)
    return json.dumps(
        {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "version": BACKUP_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def decrypt_backup(envelope: bytes, key_b64: str) -> bytes:
    parsed = json.loads(envelope)
    if parsed.get("version") != BACKUP_VERSION:
        raise ValueError("unsupported backup envelope version")
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    if len(key) != 32:
        raise ValueError("backup key must decode to exactly 32 bytes")
    return AESGCM(key).decrypt(
        base64.b64decode(parsed["nonce"]),
        base64.b64decode(parsed["ciphertext"]),
        BACKUP_AAD,
    )
