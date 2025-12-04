from __future__ import annotations

import tkinter as tk

from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from ..core.password_generator import PasswordGenerator
from ..core.vault import (
    add_credential,
    delete_credential,
    get_credential,
    list_sites,
)
from .widgets import simple_prompt

if TYPE_CHECKING:
    from .app import PasswordManagerApp


class SetupMasterFrame(ttk.Frame):
    """Screen to set an initial master password (first-time setup)."""

    def __init__(self, parent: tk.Widget, controller: PasswordManagerApp) -> None:
        super().__init__(parent)
        self.controller = controller

        ttk.Label(
            self,
            text='Create Master Password',
            font=('TkDefaultFont', 14),
        ).pack(pady=10)

        self._pw1_var = tk.StringVar()
        self._pw2_var = tk.StringVar()

        ttk.Label(self, text='Password:').pack(anchor='w', padx=20)
        ttk.Entry(self, textvariable=self._pw1_var, show='*').pack(
            fill='x',
            padx=20,
            pady=5,
        )

        ttk.Label(self, text='Confirm password:').pack(anchor='w', padx=20)
        ttk.Entry(self, textvariable=self._pw2_var, show='*').pack(
            fill='x',
            padx=20,
            pady=5,
        )

        ttk.Button(self, text='Save', command=self._on_save).pack(pady=15)

    def _on_save(self) -> None:
        """Validate the two password fields and invoke controller logic."""
        pw1 = self._pw1_var.get()
        pw2 = self._pw2_var.get()

        if pw1 != pw2:
            messagebox.showerror('Error', 'Passwords do not match.')
            return
        if not pw1:
            messagebox.showerror('Error', 'Password cannot be empty.')
            return

        self.controller.create_master_and_vault(pw1)


class LoginFrame(ttk.Frame):
    """Screen to unlock the vault using the master password."""

    def __init__(self, parent: tk.Widget, controller: PasswordManagerApp) -> None:
        super().__init__(parent)
        self.controller = controller
        self._pw_var = tk.StringVar()

        ttk.Label(self, text='Unlock Vault', font=('TkDefaultFont', 14)).pack(pady=10)

        ttk.Label(self, text='Master password:').pack(anchor='w', padx=20)
        ttk.Entry(self, textvariable=self._pw_var, show='*').pack(
            fill='x',
            padx=20,
            pady=10,
        )

        ttk.Button(self, text='Unlock', command=self._on_unlock).pack(pady=5)

    def _on_unlock(self) -> None:
        """Invoke controller login with the entered password."""
        pw = self._pw_var.get()
        self.controller.login(pw)


class MainMenuFrame(ttk.Frame):
    """GUI version of the CLI main menu, using the same core utilities."""

    def __init__(self, parent: tk.Widget, controller: PasswordManagerApp) -> None:
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text='Password Manager', font=('TkDefaultFont', 14)).pack(pady=10)

        ttk.Button(self, text='Generate password', command=self._generate).pack(
            fill='x',
            padx=50,
            pady=5,
        )
        ttk.Button(self, text='Store credential', command=self._store).pack(
            fill='x',
            padx=50,
            pady=5,
        )
        ttk.Button(self, text='Retrieve credential', command=self._retrieve).pack(
            fill='x',
            padx=50,
            pady=5,
        )
        ttk.Button(self, text='Delete credential', command=self._delete).pack(
            fill='x',
            padx=50,
            pady=5,
        )
        ttk.Button(self, text='List sites', command=self._list_sites).pack(
            fill='x',
            padx=50,
            pady=5,
        )
        ttk.Button(
            self,
            text='See all credentials',
            command=self._see_all,
        ).pack(
            fill='x',
            padx=50,
            pady=5,
        )

    def _require_unlocked(self) -> bool:
        """
        Check that the vault is unlocked (i.e., we have a key).

        Returns:
            True if unlocked, False otherwise (in which case an error is shown).
        """
        if self.controller.key is None:
            messagebox.showerror('Error', 'Vault is not unlocked.')
            return False
        return True

    def _generate(self) -> None:
        """Generate a random password and show it in a dialog."""
        generator = PasswordGenerator(length=16)
        password = generator.generate_password()
        messagebox.showinfo('Generated Password', password)

    def _store(self) -> None:
        """Prompt user for credential details and save them to the vault."""
        if not self._require_unlocked():
            return

        key = self.controller.key
        assert key is not None

        site = simple_prompt(self, 'Site')
        if site is None:
            return

        username = simple_prompt(self, 'Username')
        if username is None:
            return

        auto = messagebox.askyesno(
            'Password',
            'Generate password automatically?',
        )

        if auto:
            password = PasswordGenerator().generate_password()
        else:
            password = simple_prompt(self, 'Password', hide=True) or ''
        notes = simple_prompt(self, 'Notes (optional)') or ''

        try:
            add_credential(site, username, password, notes, key)
        except Exception as exc:  # pragma: no cover
            messagebox.showerror('Error', f'Failed to store credential: {exc}')
            return

        messagebox.showinfo('Success', 'Credential stored.')

    def _retrieve(self) -> None:
        """Retrieve and display a credential for a given site."""
        if not self._require_unlocked():
            return

        key = self.controller.key
        assert key is not None

        site = simple_prompt(self, 'Site')
        if site is None:
            return

        try:
            cred = get_credential(site, key)
        except Exception as exc:  # pragma: no cover
            messagebox.showerror('Error', f'Failed to read vault: {exc}')
            return

        if not cred:
            messagebox.showerror('Error', 'Site not found.')
            return

        messagebox.showinfo(
            'Credential',
            (f'Site: {site}\nUsername: {cred["username"]}\nPassword: {cred["password"]}\nNotes: {cred["notes"]}'),
        )

    def _delete(self) -> None:
        """Delete a credential from the vault."""
        if not self._require_unlocked():
            return

        key = self.controller.key
        assert key is not None

        site = simple_prompt(self, 'Site to delete')
        if site is None:
            return

        try:
            deleted = delete_credential(site, key)
        except Exception as exc:  # pragma: no cover
            messagebox.showerror('Error', f'Failed to modify vault: {exc}')
            return

        if deleted:
            messagebox.showinfo('Deleted', 'Credential deleted.')
        else:
            messagebox.showerror('Error', 'Site not found.')

    def _list_sites(self) -> None:
        """List all sites currently stored in the vault."""
        if not self._require_unlocked():
            return

        key = self.controller.key
        assert key is not None

        try:
            sites = list_sites(key)
        except Exception as exc:  # pragma: no cover
            messagebox.showerror('Error', f'Failed to read vault: {exc}')
            return

        if not sites:
            messagebox.showinfo('Sites', 'No credentials stored.')
            return

        messagebox.showinfo('Sites', '\n'.join(sites))

    def _see_all(self) -> None:
        """
        Show all credentials (site, username, password, notes)
        in a table inside a separate window.
        """
        if not self._require_unlocked():
            return

        key = self.controller.key
        assert key is not None

        try:
            sites = list_sites(key)
        except Exception as exc:  # pragma: no cover
            messagebox.showerror('Error', f'Failed to read vault: {exc}')
            return

        if not sites:
            messagebox.showinfo('Credentials', 'No credentials stored.')
            return

        window = tk.Toplevel(self)
        window.title('All Credentials')
        window.geometry('800x300')

        frame = ttk.Frame(window)
        frame.pack(fill='both', expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        columns = ('site', 'username', 'password', 'notes')
        tree = ttk.Treeview(frame, columns=columns, show='headings')

        tree.heading('site', text='Site')
        tree.heading('username', text='Username')
        tree.heading('password', text='Password')
        tree.heading('notes', text='Notes')

        tree.column('site', width=150, anchor='w')
        tree.column('username', width=150, anchor='w')
        tree.column('password', width=150, anchor='w')
        tree.column('notes', width=300, anchor='w')

        vscroll = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        hscroll = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)

        tree.grid(row=0, column=0, sticky='nsew')
        vscroll.grid(row=0, column=1, sticky='ns')
        hscroll.grid(row=1, column=0, sticky='ew')

        for site in sites:
            try:
                cred = get_credential(site, key)
            except Exception:
                continue

            if not cred:
                continue

            tree.insert(
                '',
                'end',
                values=(site, cred['username'], cred['password'], cred['notes']),
            )
