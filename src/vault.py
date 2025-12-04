from __future__ import annotations

import json
import os

from typing import Dict, List, Optional, TypedDict

from .crypto_utils import decrypt_bytes, encrypt_bytes

VAULT_FILE = 'vault.bin'


class Credential(TypedDict):
    """Schema for a single saved credential."""

    username: str
    password: str
    notes: str


Vault = Dict[str, Credential]


def init_empty_vault(key: bytes) -> None:
    """
    Create an empty encrypted vault file on disk.

    Args:
        key: Fernet key used to encrypt the vault.
    """
    vault: Vault = {}
    save_vault(vault, key)
    print('[+] Created new empty vault.\n')


def load_vault(key: bytes) -> Vault:
    """
    Load and decrypt the vault file.

    Args:
        key: Fernet key used to decrypt the vault.

    Returns:
        The decrypted vault dictionary.

    Raises:
        FileNotFoundError: If the vault file does not exist.
    """
    if not os.path.exists(VAULT_FILE):
        msg = f'{VAULT_FILE} not found'
        raise FileNotFoundError(msg)

    with open(VAULT_FILE, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_bytes(encrypted_data, key)
    return json.loads(decrypted_data.decode('utf-8'))


def save_vault(vault: Vault, key: bytes) -> None:
    """
    Encrypt and persist the vault to disk.

    Args:
        vault: Vault dictionary to save.
        key: Fernet key.
    """
    data_bytes = json.dumps(vault, indent=2).encode('utf-8')
    encrypted_bytes = encrypt_bytes(data_bytes, key)

    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted_bytes)


def add_credential(
    site: str,
    username: str,
    password: str,
    notes: str,
    key: bytes,
) -> None:
    """
    Add or update a credential for a site.

    Args:
        site: Site or service name (dictionary key).
        username: Account username.
        password: Account password.
        notes: Free-form notes.
        key: Fernet key.
    """
    vault = load_vault(key)
    vault[site] = {
        'username': username,
        'password': password,
        'notes': notes,
    }
    save_vault(vault, key)


def get_credential(site: str, key: bytes) -> Optional[Credential]:
    """
    Retrieve a credential by site.

    Args:
        site: Site or service name.
        key: Fernet key.

    Returns:
        Credential dict if found, otherwise None.
    """
    vault = load_vault(key)
    return vault.get(site)


def delete_credential(site: str, key: bytes) -> bool:
    """
    Delete a credential for a site.

    Args:
        site: Site or service name.
        key: Fernet key.

    Returns:
        True if the site existed and was deleted, False otherwise.
    """
    vault = load_vault(key)

    if site in vault:
        del vault[site]
        save_vault(vault, key)
        return True

    return False


def list_sites(key: bytes) -> List[str]:
    """
    List all site keys stored in the vault.

    Args:
        key: Fernet key.

    Returns:
        Sorted list of site names.
    """
    vault = load_vault(key)
    return sorted(vault.keys())
