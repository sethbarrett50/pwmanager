from __future__ import annotations

import os
import tkinter as tk

from tkinter import messagebox, ttk

from ..core.auth import AuthManager
from ..core.crypto_utils import derive_key_from_master
from ..core.vault import VAULT_FILE, init_empty_vault
from .frames import LoginFrame, MainMenuFrame, SetupMasterFrame


class PasswordManagerApp(tk.Tk):
    """
    Top-level Tkinter application for the password manager.

    This GUI is a thin layer over the core auth/crypto/vault utilities:
    - AuthManager manages the master password hash in master.hash.
    - The vault is stored in an encrypted file (vault.bin).
    """

    WINDOW_WIDTH = 500
    WINDOW_HEIGHT = 300

    def __init__(self) -> None:
        super().__init__()

        self.title('Password Manager')
        self.geometry(f'{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}')
        self.minsize(self.WINDOW_WIDTH, self.WINDOW_HEIGHT)

        self.auth = AuthManager()
        self.key: bytes | None = None

        container = ttk.Frame(self)
        container.pack(fill='both', expand=True)
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self._frames: dict[type[ttk.Frame], ttk.Frame] = {}

        for FrameClass in (SetupMasterFrame, LoginFrame, MainMenuFrame):
            frame = FrameClass(parent=container, controller=self)
            self._frames[FrameClass] = frame
            frame.grid(row=0, column=0, sticky='nsew')

        self.show_initial_frame()

    def _master_hash_exists(self) -> bool:
        """Return True if the master hash file exists on disk."""
        return os.path.exists(self.auth.hash_file)

    def _vault_exists(self) -> bool:
        """
        Return True if the vault file exists and is non-empty.

        An empty file is treated as "no usable vault yet".
        """
        return os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0

    def _ensure_vault_initialized(self) -> None:
        """
        Ensure that an encrypted vault file exists.

        Called after successful login or master creation, using the
        already-derived key. If the vault file is missing or empty,
        a new empty vault is created.
        """
        if self.key is None:
            messagebox.showerror(
                'Error',
                'Vault cannot be initialized because no key is available.',
            )
            return

        if not self._vault_exists():
            try:
                init_empty_vault(self.key)
            except Exception as exc:  # pragma: no cover
                messagebox.showerror(
                    'Error',
                    f'Failed to initialize vault: {exc}',
                )

    def show_frame(self, frame_class: type[ttk.Frame]) -> None:
        """Raise the specified frame class to the top."""
        frame = self._frames[frame_class]
        frame.tkraise()

    def show_initial_frame(self) -> None:
        """
        Decide which screen to show first.

        - If master.hash does not exist, go to master password setup.
        - If master.hash exists, load it and go to login.
        """
        if not self._master_hash_exists():
            self.show_frame(SetupMasterFrame)
            return

        try:
            if not self.auth.load_master_password():
                messagebox.showerror(
                    'Error',
                    'Failed to load master password data. You may need to delete the existing master.hash file.',
                )
                self.show_frame(SetupMasterFrame)
                return
        except Exception as exc:  # pragma: no cover
            messagebox.showerror(
                'Error',
                f'Master password data is corrupted: {exc}\n'
                'You may need to remove master.hash and recreate your vault.',
            )
            self.show_frame(SetupMasterFrame)
            return

        self.show_frame(LoginFrame)

    def create_master_and_vault(self, password: str) -> None:
        """
        Called by SetupMasterFrame when the user sets a master password.

        This method:
        - Stores the master password hash via AuthManager.
        - Derives the encryption key.
        - Creates an empty encrypted vault if needed.
        - Transitions to the main menu.
        """
        try:
            self.auth.set_master_password(password)
        except Exception as exc:  # pragma: no cover
            messagebox.showerror(
                'Error',
                f'Failed to store master password: {exc}',
            )
            return

        key = derive_key_from_master(
            password,
            self.auth.salt or b'',  # type: ignore[arg-type]
            self.auth.iterations,
        )
        self.key = key

        self._ensure_vault_initialized()

        messagebox.showinfo('Success', 'Master password created.')
        self.show_frame(MainMenuFrame)

    def login(self, password: str) -> None:
        """
        Called by LoginFrame when the user attempts to unlock the vault.

        This method:
        - Verifies the password against master.hash via AuthManager.
        - Derives the encryption key if verification succeeds.
        - Ensures the vault file exists.
        - Transitions to the main menu.
        """
        if not self.auth.verify_password(password):
            messagebox.showerror('Error', 'Invalid master password.')
            return

        self.key = derive_key_from_master(
            password,
            self.auth.salt or b'',  # type: ignore[arg-type]
            self.auth.iterations,
        )
        self._ensure_vault_initialized()
        self.show_frame(MainMenuFrame)


def main() -> None:
    """Entry point for launching the Tkinter GUI."""
    app = PasswordManagerApp()
    app.mainloop()


if __name__ == '__main__':
    main()
