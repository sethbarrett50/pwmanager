from __future__ import annotations

import sys

from getpass import getpass

from .auth import AuthManager
from .crypto_utils import derive_key_from_master
from .password_generator import PasswordGenerator
from .vault import (
    add_credential,
    delete_credential,
    get_credential,
    init_empty_vault,
    list_sites,
)


def initialize_system(auth: AuthManager) -> None:
    """
    Ensure a master password and vault exist.

    If no master password hash file is present, the user is prompted
    to create one and an empty vault is initialized.
    """
    loaded = auth.load_master_password()

    if not loaded:
        print('[*] No master password found.')
        success = auth.create_master_password()

        if not success:
            print('[!] Could not create master password. Exiting.')
            sys.exit(1)

        if not auth.load_master_password():
            print('[!] Failed to reload master password. Exiting.')
            sys.exit(1)

        master = getpass('Re-enter master password to initialize vault: ')
        key = derive_key_from_master(
            master,
            auth.salt or b'',  # type: ignore[arg-type]
            auth.iterations,
        )
        init_empty_vault(key)


def login(auth: AuthManager) -> bytes:
    """
    Authenticate and derive the encryption key.

    Returns:
        A Fernet key derived from the master password.

    Exits the program after three failed attempts.
    """
    for _ in range(3):
        success = auth.verify_login()

        if success:
            master = getpass('Re-enter password to unlock vault: ')
            return derive_key_from_master(
                master,
                auth.salt or b'',  # type: ignore[arg-type]
                auth.iterations,
            )

        print('Try again.\n')

    print('[!] Too many failed attempts. Exiting.')
    sys.exit(1)


def action_generate_password() -> None:
    """Generate a password and display it to the user."""
    length_input = input('Length (default 16): ').strip()
    length = 16

    if length_input.isdigit():
        length = int(length_input)

    generator = PasswordGenerator(length=length)
    password = generator.generate_password()
    print('Generated password:', password, '\n')


def action_store_credential(key: bytes) -> None:
    """Prompt for credential details and store them in the vault."""
    site = input('Site: ').strip()
    username = input('Username: ').strip()
    auto = input('Generate password automatically? (Y/n): ').strip().lower()

    if auto == 'n':
        password = getpass('Password: ')
    else:
        password = PasswordGenerator().generate_password()
        print('Generated password:', password)

    notes = input('Notes (optional): ').strip()

    add_credential(site, username, password, notes, key)
    print('[+] Credential saved.\n')


def action_retrieve_credential(key: bytes) -> None:
    """Look up a credential by site and display it."""
    site = input('Site: ').strip()
    cred = get_credential(site, key)

    if not cred:
        print('[!] Site not found.\n')
        return

    print('\nSite:', site)
    print('Username:', cred['username'])
    print('Password:', cred['password'])
    print('Notes:', cred['notes'], '\n')


def action_delete_credential(key: bytes) -> None:
    """Delete a credential from the vault."""
    site = input('Site: ').strip()
    deleted = delete_credential(site, key)

    if deleted:
        print('[+] Deleted.\n')
    else:
        print('[!] Site not found.\n')


def action_list_sites(key: bytes) -> None:
    """List all sites for which credentials are stored."""
    sites = list_sites(key)

    if not sites:
        print('[!] No credentials stored.\n')
        return

    print('Stored sites:')
    for site in sites:
        print(f' - {site}')
    print()


def show_menu() -> str:
    """Print the main menu and return the user's choice."""
    print('===== Password Manager =====')
    print('1) Generate password')
    print('2) Store credential')
    print('3) Retrieve credential')
    print('4) Delete credential')
    print('5) List sites')
    print('6) Quit')
    return input('Select an option: ').strip()


def main() -> None:
    """Main entry point for the CLI."""
    auth = AuthManager()
    initialize_system(auth)
    key = login(auth)

    while True:
        choice = show_menu()
        print()

        if choice == '1':
            action_generate_password()
        elif choice == '2':
            action_store_credential(key)
        elif choice == '3':
            action_retrieve_credential(key)
        elif choice == '4':
            action_delete_credential(key)
        elif choice == '5':
            action_list_sites(key)
        elif choice == '6':
            print('Goodbye.')
            sys.exit(0)
        else:
            print('Invalid selection.\n')


if __name__ == '__main__':
    main()
