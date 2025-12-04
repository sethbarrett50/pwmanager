from __future__ import annotations

import base64
import hashlib

from typing import Final

from cryptography.fernet import Fernet

DEFAULT_ITERATIONS: Final[int] = 200_000


def derive_key_from_master(
    master_password: str,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    """
    Derive a Fernet-compatible key from the master password and salt.

    Args:
        master_password: Plain-text master password.
        salt: Random salt bytes (same used when hashing).
        iterations: PBKDF2 iteration count.

    Returns:
        URL-safe base64-encoded key suitable for Fernet.
    """
    password_bytes = master_password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        iterations,
    )
    return base64.urlsafe_b64encode(dk)


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """
    Encrypt raw bytes using Fernet.

    Args:
        data: Plain-text bytes.
        key: Fernet key derived by derive_key_from_master.

    Returns:
        Encrypted token bytes.
    """
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    """
    Decrypt bytes previously produced by encrypt_bytes.

    Args:
        token: Encrypted token bytes.
        key: Fernet key.

    Returns:
        Decrypted plain-text bytes.
    """
    f = Fernet(key)
    return f.decrypt(token)
