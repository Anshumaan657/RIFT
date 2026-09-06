"""Authenticated encryption for bearer tokens and raw evidence references."""

import base64
import binascii
import json
import os
from collections.abc import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rift.settings import get_settings


class EncryptionError(ValueError):
    pass


class EncryptionService:
    VERSION = 1

    def __init__(self, master_key_b64: str | None = None) -> None:
        encoded = master_key_b64 or get_settings().master_key_b64.get_secret_value()
        try:
            key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, binascii.Error) as exc:
            raise EncryptionError("master key must be URL-safe base64") from exc
        if len(key) != 32:
            raise EncryptionError("master key must decode to exactly 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: str, *, purpose: str, record_id: str) -> str:
        nonce = os.urandom(12)
        aad = f"rift:v{self.VERSION}:{purpose}:{record_id}".encode()
        ciphertext = self._cipher.encrypt(nonce, plaintext.encode(), aad)
        envelope = {
            "v": self.VERSION,
            "nonce": base64.urlsafe_b64encode(nonce).decode(),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
        }
        return json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    def decrypt(self, envelope_json: str, *, purpose: str, record_id: str) -> str:
        try:
            envelope: Mapping[str, object] = json.loads(envelope_json)
            if envelope.get("v") != self.VERSION:
                raise EncryptionError("unsupported encrypted envelope version")
            nonce = base64.urlsafe_b64decode(str(envelope["nonce"]))
            ciphertext = base64.urlsafe_b64decode(str(envelope["ciphertext"]))
            aad = f"rift:v{self.VERSION}:{purpose}:{record_id}".encode()
            return self._cipher.decrypt(nonce, ciphertext, aad).decode()
        except EncryptionError:
            raise
        except Exception as exc:
            raise EncryptionError("encrypted value is invalid or was tampered with") from exc

    def encrypt_token(self, token: str, record_id: str) -> str:
        return self.encrypt(token, purpose="bearer-token", record_id=record_id)

    def decrypt_token(self, value: str, record_id: str) -> str:
        return self.decrypt(value, purpose="bearer-token", record_id=record_id)
