#!/usr/bin/env python3
"""PassGuard application entry point."""
from __future__ import annotations
import sys
import tkinter as tk
from tkinter import messagebox

from passguard.config import WORDLIST_PATH
from passguard.wordlist import load_wordlist_candidates
from passguard.gui import PasswordAuditorApp
from passguard.cli import cli_main

def main() -> None:
    if "--cli" in sys.argv:
        cli_main()
        return

    root = tk.Tk()
    try:
        candidates = load_wordlist_candidates(WORDLIST_PATH)
        wordlist = {candidate.casefold() for candidate in candidates}
    except (OSError, UnicodeError) as error:
        messagebox.showerror(
            "Unable to load the wordlist",
            f"Unable to open {WORDLIST_PATH.name}:\n{error}",
            parent=root,
        )
        root.destroy()
        return

    PasswordAuditorApp(root, wordlist, candidates)
    root.mainloop()

if __name__ == "__main__":
    main()
