"""Versioned local encrypted-vault core for Password Service.

This module is intentionally independent from Tkinter and the legacy
``passwords.md`` storage path. It never logs or persists the master password.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Iterable, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


VAULT_VERSION = 1
KDF_NAME = "Argon2id"
CIPHER_NAME = "AES-256-GCM"
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
MIN_MEMORY_COST_KIB = 8 * 1024
MAX_MEMORY_COST_KIB = 256 * 1024
MIN_ITERATIONS = 1
MAX_ITERATIONS = 10
MIN_LANES = 1
MAX_LANES = 16
MIN_CIPHERTEXT_LENGTH = 16 + len(b'{"records":[]}')

DEFAULT_KDF_PARAMETERS = {
    "memory_cost_kib": 64 * 1024,
    "iterations": 3,
    "lanes": 4,
}

_GENERIC_AUTH_ERROR = "Invalid master password or corrupted vault"
_ENVELOPE_FIELDS = {"version", "kdf", "salt", "cipher", "nonce", "ciphertext"}
_KDF_FIELDS = {"name", "memory_cost_kib", "iterations", "lanes"}


class VaultAuthenticationError(ValueError):
    """Raised when authentication fails or the vault is invalid/corrupted."""


def _require_master_password(master_password: str) -> bytes:
    if not isinstance(master_password, str):
        raise TypeError("Master password must be a string")
    if not master_password:
        raise ValueError("Master password must not be empty")
    return master_password.encode("utf-8")


def _normalize_records(records: Iterable[Mapping[str, str]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {"name", "password"}:
            raise ValueError("Each record must contain exactly 'name' and 'password'")
        name = record["name"]
        password = record["password"]
        if not isinstance(name, str) or not isinstance(password, str):
            raise TypeError("Record names and passwords must be strings")
        normalized.append({"name": name, "password": password})
    return normalized


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: object, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR) from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    return decoded


def _validate_kdf_parameters(kdf: object) -> dict[str, int | str]:
    if not isinstance(kdf, dict) or set(kdf) != _KDF_FIELDS:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    if kdf.get("name") != KDF_NAME:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)

    memory_cost = kdf.get("memory_cost_kib")
    iterations = kdf.get("iterations")
    lanes = kdf.get("lanes")
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (memory_cost, iterations, lanes)):
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    if not MIN_MEMORY_COST_KIB <= memory_cost <= MAX_MEMORY_COST_KIB:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    if not MIN_LANES <= lanes <= MAX_LANES:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    return {
        "name": KDF_NAME,
        "memory_cost_kib": memory_cost,
        "iterations": iterations,
        "lanes": lanes,
    }


def _metadata(version: int, kdf: Mapping[str, int | str], salt_b64: str, cipher: str) -> dict[str, object]:
    return {
        "version": version,
        "kdf": dict(kdf),
        "salt": salt_b64,
        "cipher": cipher,
    }


def _associated_data(metadata: Mapping[str, object]) -> bytes:
    return json.dumps(metadata, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_key(master_password: bytes, salt: bytes, kdf: Mapping[str, int | str]) -> bytes:
    return Argon2id(
        salt=salt,
        length=KEY_LENGTH,
        iterations=int(kdf["iterations"]),
        lanes=int(kdf["lanes"]),
        memory_cost=int(kdf["memory_cost_kib"]),
    ).derive(master_password)


def _validate_envelope(
    envelope: Mapping[str, object],
) -> tuple[dict[str, int | str], bytes, bytes, bytes, dict[str, object]]:
    """Validate all attacker-controlled metadata before running the KDF."""

    if not isinstance(envelope, Mapping) or set(envelope) != _ENVELOPE_FIELDS:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)

    version = envelope.get("version")
    cipher = envelope.get("cipher")
    if type(version) is not int or version != VAULT_VERSION:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
    if not isinstance(cipher, str) or cipher != CIPHER_NAME:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)

    kdf = _validate_kdf_parameters(envelope.get("kdf"))
    salt_value = envelope.get("salt")
    salt = _b64decode(salt_value, expected_length=SALT_LENGTH)
    nonce = _b64decode(envelope.get("nonce"), expected_length=NONCE_LENGTH)
    ciphertext = _b64decode(envelope.get("ciphertext"))
    if len(ciphertext) < MIN_CIPHERTEXT_LENGTH:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)

    metadata = _metadata(VAULT_VERSION, kdf, str(salt_value), CIPHER_NAME)
    return kdf, salt, nonce, ciphertext, metadata


def encrypt_vault(master_password: str, records: Iterable[Mapping[str, str]]) -> dict[str, object]:
    """Encrypt records and return a versioned JSON-compatible envelope."""

    password_bytes = _require_master_password(master_password)
    normalized = _normalize_records(records)
    payload = json.dumps(
        {"records": normalized},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    kdf: dict[str, int | str] = {"name": KDF_NAME, **DEFAULT_KDF_PARAMETERS}
    salt_b64 = _b64encode(salt)
    metadata = _metadata(VAULT_VERSION, kdf, salt_b64, CIPHER_NAME)
    key = _derive_key(password_bytes, salt, kdf)
    ciphertext = AESGCM(key).encrypt(nonce, payload, _associated_data(metadata))

    return {
        **metadata,
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }


def decrypt_vault(master_password: str, envelope: Mapping[str, object]) -> list[dict[str, str]]:
    """Authenticate and decrypt an envelope, returning no partial plaintext on failure."""

    password_bytes = _require_master_password(master_password)
    try:
        kdf, salt, nonce, ciphertext, metadata = _validate_envelope(envelope)
        key = _derive_key(password_bytes, salt, kdf)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _associated_data(metadata))
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"records"} or not isinstance(payload["records"], list):
            raise VaultAuthenticationError(_GENERIC_AUTH_ERROR)
        return _normalize_records(payload["records"])
    except VaultAuthenticationError:
        raise
    except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR) from exc


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        finally:
            raise


def save_vault(path: str | os.PathLike[str], master_password: str, records: Iterable[Mapping[str, str]]) -> None:
    """Encrypt and atomically save all records to ``path``."""

    envelope = encrypt_vault(master_password, records)
    serialized = json.dumps(envelope, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    _atomic_write(Path(path), serialized)


def create_vault(
    path: str | os.PathLike[str],
    master_password: str,
    records: Iterable[Mapping[str, str]] = (),
) -> None:
    """Create a new vault without overwriting an existing file."""

    vault_path = Path(path)
    if vault_path.exists():
        raise FileExistsError(f"Vault already exists: {vault_path}")
    save_vault(vault_path, master_password, records)


def load_vault(path: str | os.PathLike[str], master_password: str) -> list[dict[str, str]]:
    """Load, authenticate, and decrypt a vault from disk."""

    try:
        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultAuthenticationError(_GENERIC_AUTH_ERROR) from exc
    return decrypt_vault(master_password, envelope)
