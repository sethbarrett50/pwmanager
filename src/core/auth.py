from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os

from dataclasses import dataclass
from typing import Optional

MASTER_HASH_FILE = 'master.hash'


@dataclass
class AuthManager:
    """
    Manage the master password and its PBKDF2 hash.

    The master password hash and salt are stored in a small JSON file
    on disk (by default: master.hash).
    """

    hash_file: str = MASTER_HASH_FILE
    iterations: int = 200_000
    salt: Optional[bytes] = None
    stored_hash: Optional[str] = None

    def load_master_password(self) -> bool:
        """
        Load the master password hash, salt, and iterations from disk.

        Returns:
            True if the file exists and was loaded successfully, False otherwise.
        """
        if not os.path.exists(self.hash_file):
            return False

        with open(self.hash_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.iterations = int(data.get('iterations', self.iterations))
        self.salt = base64.b64decode(data['salt'])
        self.stored_hash = data['hash']
        return True

    def _hash_password(self, password: str, salt: bytes) -> str:
        """
        Hash a password with PBKDF2-HMAC-SHA256.

        Returns:
            Base64-encoded hash string.
        """
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.iterations,
        )
        return base64.b64encode(hash_bytes).decode('ascii')

    def create_master_password(self) -> bool:
        """
        Interactively create a new master password.

        Prompts the user to enter and confirm a password. On success,
        a new salt and hash are stored on disk and kept in memory.

        Returns:
            True if the password was created successfully, False otherwise.
        """
        print('[*] Creating new master password...')

        for _ in range(3):
            pw1 = getpass.getpass('Enter master password: ')
            pw2 = getpass.getpass('Confirm master password: ')

            if not pw1:
                print('[!] Master password cannot be empty.\n')
                continue
            if pw1 != pw2:
                print('[!] Passwords do not match. Try again.\n')
                continue

            self.salt = os.urandom(16)
            self.stored_hash = self._hash_password(pw1, self.salt)

            data = {
                'salt': base64.b64encode(self.salt).decode('ascii'),
                'iterations': self.iterations,
                'hash': self.stored_hash,
            }

            with open(self.hash_file, 'w', encoding='utf-8') as f:
                json.dump(data, f)

            print('[+] Master password created.\n')
            return True

        print('[!] Failed to create a valid master password.\n')
        return False

    def verify_login(self) -> bool:
        """
        Prompt for the master password and verify it against the stored hash.

        Returns:
            True if the password is correct, False otherwise.
        """
        if self.salt is None or self.stored_hash is None:
            if not self.load_master_password():
                print('[!] No master password found on disk.')
                return False

        candidate = getpass.getpass('Master password: ')
        candidate_hash = self._hash_password(candidate, self.salt)  # type: ignore[arg-type]

        if not hmac.compare_digest(candidate_hash, self.stored_hash or ''):
            print('[!] Invalid master password.\n')
            return False

        print('[+] Authentication successful.\n')
        return True

    def set_master_password(self, password: str) -> None:
        """
        Set and persist a new master password non-interactively.

        Intended for GUI or API use. Overwrites any existing master hash.
        """
        if not password:
            raise ValueError('Master password cannot be empty.')

        self.salt = os.urandom(16)
        self.stored_hash = self._hash_password(password, self.salt)

        data = {
            'salt': base64.b64encode(self.salt).decode('ascii'),
            'iterations': self.iterations,
            'hash': self.stored_hash,
        }
        with open(self.hash_file, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def verify_password(self, password: str) -> bool:
        """
        Verify a plain-text password against the stored hash.

        Returns:
            True if the password matches, False otherwise.
        """
        if self.salt is None or self.stored_hash is None:
            if not self.load_master_password():
                return False

        candidate_hash = self._hash_password(password, self.salt)  # type: ignore
        return hmac.compare_digest(candidate_hash, self.stored_hash or '')
