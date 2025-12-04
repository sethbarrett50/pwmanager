from __future__ import annotations

import tkinter as tk

from tkinter import ttk


def simple_prompt(parent: tk.Widget, label: str, hide: bool = False) -> str | None:
    """
    Show a minimal blocking prompt dialog.

    Args:
        parent: Parent widget.
        label: Label text for the prompt.
        hide: If True, mask the input (for passwords).

    Returns:
        The entered string, or None if the user cancels.
    """
    dialog = tk.Toplevel(parent)
    dialog.transient(parent)  # type: ignore[arg-type]
    dialog.grab_set()
    dialog.title(label)

    var = tk.StringVar()

    ttk.Label(dialog, text=f'{label}:').pack(padx=10, pady=10)
    entry = ttk.Entry(dialog, textvariable=var, show='*' if hide else '')
    entry.pack(padx=10, pady=5)
    entry.focus()

    result: list[str | None] = [None]

    def on_ok() -> None:
        result[0] = var.get()
        dialog.destroy()

    def on_cancel() -> None:
        result[0] = None
        dialog.destroy()

    btn_frame = ttk.Frame(dialog)
    btn_frame.pack(pady=10)
    ttk.Button(btn_frame, text='OK', command=on_ok).pack(side='left', padx=5)
    ttk.Button(btn_frame, text='Cancel', command=on_cancel).pack(side='left', padx=5)

    parent.wait_window(dialog)
    return result[0]
