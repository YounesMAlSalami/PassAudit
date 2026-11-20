# Windows Live-SAM Validation Procedure

Execute this only in an isolated Windows test VM authorized for the assignment.

1. Record `winver` and `systeminfo`.
2. Run an elevated PowerShell session.
3. Create disposable accounts through the GUI or a secure interactive method.
4. Independently calculate the NTLM values outside the PassGuard parser.
5. Run:

```powershell
python main.py audit-windows-sam --wordlist wordlists\wordlist.txt
```

6. Confirm the report source is `live-system-regsavekeyex`.
7. Compare every extracted NT hash with the independently calculated values.
8. Confirm the weak account is weak and the strong account is not matched.
9. Confirm the unique temporary directory and hive files are removed.

If the existing parser reports `unsupported-modern-or-unrecognized`, that
means the SAM format or revision is outside the legacy RC4/DES implementation.
Do not rerun legacy decryption against that record.

No live SAM extraction is claimed until all steps above are completed on Windows
and the evidence is retained.
