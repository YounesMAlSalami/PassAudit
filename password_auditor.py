"""Compatibility facade for the original single-file Password Auditor."""
from passguard import *  # noqa: F401,F403
from passguard.gui import PasswordAuditorApp
from passguard.cli import cli_main
from main import main

if __name__ == "__main__":
    main()
