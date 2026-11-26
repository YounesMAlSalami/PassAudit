# PassGuard Password Auditor

PassGuard is a local Tkinter application for password checks, password generation, local account-password auditing, and sanitized audit reports. It uses a local wordlist and local operating-system data; it does not use a remote API or cloud service.

Use PassGuard only on systems and accounts you own or are explicitly authorized to audit.

## Features

- Check a password against the default local wordlist and estimate its strength.
- Generate passwords with configurable length and character categories using Python's `secrets` module.
- Audit Linux `/etc/shadow` entries with passlib or yescrypt verification.
- Audit local Windows SAM entries using exported registry hives and `pypykatz`.
- Export sanitized audit reports as HTML, JSON, or CSV.
- Store reports locally in SQLite and reopen, re-export, or delete them.
- Run an interactive Linux, Windows, or candidate-check menu through the CLI.


## Screenshots

### Kali Linux

<table>
  <tr>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (166).png" width="460" alt="PassGuard on Kali Linux - screenshot 166"/>
      <br/>
      <sub>Kali Linux — Screenshot 1</sub>
    </td>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (167).png" width="460" alt="PassGuard on Kali Linux - screenshot 167"/>
      <br/>
      <sub>Kali Linux — Screenshot 2</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (178).png" width="460" alt="PassGuard on Kali Linux - screenshot 178"/>
      <br/>
      <sub>Kali Linux — Screenshot 3</sub>
    </td>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (179).png" width="460" alt="PassGuard on Kali Linux - screenshot 179"/>
      <br/>
      <sub>Kali Linux — Screenshot 4</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (181).png" width="460" alt="PassGuard on Kali Linux - screenshot 181"/>
      <br/>
      <sub>Kali Linux — Screenshot 5</sub>
    </td>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (182).png" width="460" alt="PassGuard on Kali Linux - screenshot 182"/>
      <br/>
      <sub>Kali Linux — Screenshot 6</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="Assets/kali/‏‏لقطة الشاشة (183).png" width="460" alt="PassGuard on Kali Linux - screenshot 183"/>
      <br/>
      <sub>Kali Linux — Screenshot 7</sub>
    </td>
    <td></td>
  </tr>
</table>

### Windows

<table>
  <tr>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (184).png" width="460" alt="PassGuard on Windows - screenshot 184"/>
      <br/>
      <sub>Windows — Screenshot 1</sub>
    </td>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (185).png" width="460" alt="PassGuard on Windows - screenshot 185"/>
      <br/>
      <sub>Windows — Screenshot 2</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (186).png" width="460" alt="PassGuard on Windows - screenshot 186"/>
      <br/>
      <sub>Windows — Screenshot 3</sub>
    </td>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (188).png" width="460" alt="PassGuard on Windows - screenshot 188"/>
      <br/>
      <sub>Windows — Screenshot 4</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (189).png" width="460" alt="PassGuard on Windows - screenshot 189"/>
      <br/>
      <sub>Windows — Screenshot 5</sub>
    </td>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (191).png" width="460" alt="PassGuard on Windows - screenshot 191"/>
      <br/>
      <sub>Windows — Screenshot 6</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (192).png" width="460" alt="PassGuard on Windows - screenshot 192"/>
      <br/>
      <sub>Windows — Screenshot 7</sub>
    </td>
    <td align="center">
      <img src="Assets/windows/‏‏لقطة الشاشة (193).png" width="460" alt="PassGuard on Windows - screenshot 193"/>
      <br/>
      <sub>Windows — Screenshot 8</sub>
    </td>
  </tr>
</table>


## Supported Platforms and Audits

| Capability | Supported implementation |
|---|---|
| Password check and strength estimate | All systems supported by the Tkinter application |
| Password generation | All systems supported by the Tkinter application |
| Linux account audit | Local Linux hosts with read access to `/etc/shadow` |
| Windows account audit | Local Windows hosts with elevated registry access |

The Linux auditor verifies:

- SHA-512 crypt (`$6$`)
- SHA-256 crypt (`$5$`)
- MD5 crypt (`$1$`)
- Traditional DES crypt
- Yescrypt (`$y$`) when the `yescrypt` package is installed

The Linux passlib context does not include bcrypt. The password utility can identify bcrypt and traditional DES formats, but the Linux audit verifier does not include bcrypt and must report it as unsupported.

The Windows auditor:

- Runs only when `sys.platform == "win32"`.
- Exports the `HKLM\SAM` and `HKLM\SYSTEM` hives with `reg save`.
- Parses local users and NT hashes with `pypykatz`.
- Validates NT hashes as 32-character hexadecimal values.
- Computes candidate NTLM hashes from UTF-16-LE password bytes using PyCryptodome MD4.

The application does not provide an arbitrary hash-file import workflow. It obtains Windows NT hashes only through local SAM extraction.

## GUI

The GUI entry point creates a 1180×780 Tkinter window with four pages:

1. **Dashboard** - Enter a password to check it against the loaded wordlist and view a strength score, character categories, estimated character pool, estimated search space, and recommendations.
2. **Account Audit** - Select a Linux or Windows audit, view progress and account results, inspect masked hash details, and export an active report.
3. **Password Generator** - Select a length and character categories, generate a password using `secrets`, show or hide it, copy it, or clear it.
4. **Reports** - View report metrics and account details, open or delete SQLite history entries, and export or re-export reports.

The GUI also reloads the wordlist from `wordlists/wordlist.txt` when **Reload Wordlist** is selected.

## Wordlist Processing

The default file is [wordlists/wordlist.txt](wordlists/wordlist.txt). It contains about 99,840 non-empty candidate lines. The application:

- Reads the file with UTF-8-sig encoding.
- Removes leading and trailing whitespace.
- Ignores empty lines.
- Normalizes candidates with `casefold()` for membership checks.
- Reloads the file from disk without restarting the application.

A wordlist match is evidence that the supplied candidate appeared in this local list. A non-match does not prove that a password is strong or uncompromised.

## Strength and Generation

Password strength uses `zxcvbn` when it is available. If import or scoring fails, the application uses a local fallback based on password length, character diversity, and repeated characters.

The score is shown as 0–100 and is mapped to:

- Very Weak
- Weak
- Moderate
- Strong
- Very Strong

Generated passwords ensure that each selected character category appears at least once when the requested length can accommodate it. The generator rejects lengths below 4 characters, configurations with no character category, and lengths that are too short for every selected category.

These results are estimates, not guarantees of password security.

## Reports and Audit History

The GUI reports audit date, operating system, audit type, account totals, weak matches, non-matches, unsupported hashes, errors, and elapsed duration.

Exports are available through Save File dialogs in:

- HTML (`.html`)
- JSON (`.json`)
- CSV (`.csv`)

Exports contain report metadata, account hash metadata, masked hash previews, errors, and recommendations. Plaintext passwords and complete hash values are excluded.

The GUI full-hash display is protected by platform privilege checks and confirmation. On Linux, it requires root. On Windows, it requires elevation. Full hashes are never added to exports or SQLite history.

The GUI stores sanitized report history in `reports/audit_history.sqlite3`. Its report history supports:

- Opening a previous report
- Re-exporting a previous report
- Deleting a history entry
- Recording selected export paths

If report history or export storage fails, the application reports the failure. A report that cannot be saved to SQLite is available only for the current session when otherwise possible.

## Requirements

- Python 3.10 or newer for the source syntax currently used
- Tkinter/Tcl-Tk provided by the operating system
- [requirements.txt](requirements.txt):
  - `pycryptodome>=3.20`
  - `pypykatz>=0.6`
  - `passlib>=1.7`
  - `zxcvbn>=4.4`
  - `yescrypt>=1.0`
  - `pytest>=8.0`

Pytest is used for tests and is not required to launch the application.

## Download the Repository

The repository remote is:

```text
https://github.com/YounesMAlSalami/PassAudit.git
```

### Clone with Git

```bash
git clone https://github.com/YounesMAlSalami/PassAudit.git
cd PassAudit
```

Your local directory name may differ if you clone into a custom destination.

### Download a ZIP

1. Open <https://github.com/YounesMAlSalami/PassAudit>.
2. Click **Code**.
3. Select **Download ZIP**.
4. Extract the archive.
5. Open PowerShell or a terminal in the extracted project directory.

## Windows Installation

The setup below uses a virtual environment and PowerShell.

1. Install Python 3.10 or newer and verify `py` is available.
2. Clone or extract the repository.
3. Open PowerShell in the project directory.
4. Create and activate a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Tkinter should be included with the standard Python installation on typical Windows distributions. If `tkinter` is missing, repair or reinstall Python with the Tk/Tcl feature included.

If PowerShell prevents activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

This changes policy only for the current PowerShell process.

Windows account auditing requires an elevated PowerShell or application session and working access to the local SAM and SYSTEM hives. SAM support can vary with Windows configuration, registry policy, and `pypykatz` compatibility.

## Linux — Kali / Debian / Ubuntu

Install Python, Tkinter, and virtual-environment support, then install the project dependencies:

```bash
sudo apt update
sudo apt install -y python3-full python3-venv python3-tk
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Do not use `sudo pip` or force system-package overrides.

The Linux audit reads `/etc/shadow` directly. A normal user normally cannot read that file, and the application does not alter its permissions or automatically elevate itself. Start it through an approved elevated session when necessary:

```bash
sudo -E .venv/bin/python main.py
```

For an interactive CLI session with the same privileges:

```bash
sudo -E .venv/bin/python main.py --cli
```

Do not change `/etc/shadow` permissions to enable an audit.

## Running the GUI

Run the GUI from the project root after activating the virtual environment.

### Windows

```powershell
python main.py
```

#### Windows - Run GUI as Administrator

Use an elevated PowerShell window when you need to perform the Windows account audit and access the local SAM and SYSTEM hives.

1. Open the Start menu.
2. Search for **PowerShell**.
3. Right-click **Windows PowerShell** or **PowerShell**.
4. Select **Run as administrator**.
5. Confirm the UAC prompt.
6. Navigate to the actual PassGuard project directory.
7. Activate the existing virtual environment.
8. Launch the GUI from the same elevated window.

Replace `C:\Path\To\PassGuard` below with the location where you cloned or extracted the project:

```powershell
cd "C:\Path\To\PassGuard"
.\.venv\Scripts\Activate.ps1
python main.py
OR 
.\.venv\Scripts\python.exe main.py
```

If the virtual environment has not been created or the dependencies have not been installed, complete the [Windows Installation](#windows-installation) section first.

Running the GUI through elevated PowerShell allows the Windows account-audit workflow to request administrative access to the local SAM and SYSTEM hives. Elevation does not guarantee that the audit will succeed; registry policy, Windows configuration, and parser compatibility may still prevent it from completing.

For password checking and password generation, a normal non-elevated PowerShell window is sufficient.

### Linux

```bash
python main.py
```

#### Linux - Run GUI with `sudo`

Run the GUI with elevated privileges from the project root when you need to audit local Linux accounts and read `/etc/shadow`:

```bash
sudo -E .venv/bin/python main.py
```

The virtual environment must already exist and contain the project dependencies. If it has not been created or the dependencies have not been installed, complete the [Linux - Kali / Debian / Ubuntu](#linux--kali--debian--ubuntu) section first.

PassGuard does not change `/etc/shadow` permissions or request privilege escalation internally. The GUI can be launched without `sudo` for password checking and password generation, but the Linux account-audit workflow will fail with a permissions error if `/etc/shadow` is not readable.

The application does not need to be installed as a system package.

### GUI Troubleshooting

- `No module named tkinter`: install Tkinter with your operating system package manager. On Debian or Kali, use `python3-tk`.
- `No module named ...`: activate the virtual environment and rerun `python -m pip install -r requirements.txt`.
- Linux audit permission error: `/etc/shadow` is not readable by the current process.
- Windows audit cannot export or parse SAM: run in an elevated session and verify local SAM/SYSTEM access.
- Reports cannot be created or saved: verify write permission for the project `reports` directory and the selected export location.

## Running the CLI

Start the interactive menu from the project root:

```bash
python main.py --cli
```

The menu provides:

1. **Audit Linux Passwords (/etc/shadow)** - available only on Linux. The process must be able to read `/etc/shadow`.
2. **Audit Windows Accounts (SAM)** - available only on Windows. The process must be elevated and able to export and parse the SAM and SYSTEM hives.
3. **Check a Candidate Password** - prompts securely for a password and compares it with the default wordlist. It does not display or perform strength analysis in this menu.
4. **Exit**

The CLI Linux audit prints account state and masked matched-candidate details. The CLI candidate check does not accept a password on the command line and does not save audit reports.

The CLI does not accept:

- Arbitrary hash-file paths
- Arbitrary wordlist paths
- Export format arguments
- Separate audit subcommands

## Tests

Run the test suite from the project root:

```bash
python -m pytest tests -v
```

The tests cover password strength categories, password generation, wordlist lookup, Linux hash detection, report redaction and HTML/JSON/CSV export, NT hash validation, and SQLite history round-trips.

These tests do not replace live `/etc/shadow` or Windows SAM integration tests.

## Project Structure

```text
main.py                 GUI and CLI entry point
password_auditor.py     Compatibility export facade
passguard/
  __init__.py
  audit_history.py      SQLite report-history store
  cli.py                Interactive CLI menu
  config.py             Project and report paths
  gui.py                Tkinter interface
  linux_auditor.py      /etc/shadow wordlist verification
  password_utils.py     Strength, generation, and masking helpers
  reporting.py          Sanitized report model and exporters
  windows_auditor.py    SAM hive extraction and NTLM verification
  wordlist.py           Wordlist loading and lookup
wordlists/
  wordlist.txt          Default candidate list
tests/
  test_assignment4.py
  test_reports.py
Assets/
  kali/                 Kali interface screenshots
  windows/              Windows interface screenshots
LICENSE
requirements.txt
README.md
```


## Technical Notes and Limitations

- **Linux GUI audit:** The current GUI implementation passes stop-event and resource-limit parameters that the Linux audit function does not accept. As a result, the Linux GUI audit workflow is currently blocked by a function signature mismatch.
- **Linux CLI audit:** The Linux CLI calls the audit function without the unsupported parameters and is the currently compatible interface for local Linux account auditing.
- **Windows audit:** The Windows auditor requires elevated privileges and access to the local SAM and SYSTEM registry hives. Successful extraction and parsing may depend on Windows configuration, registry policy, and `pypykatz` compatibility.
- **Hash format support:** The Linux audit verifier supports SHA-512 crypt, SHA-256 crypt, MD5 crypt, traditional DES crypt, and yescrypt when the required package is installed. Unsupported hash formats must not be treated as successful password audits.
- **Password strength estimation:** Strength scores are heuristic estimates. The fallback implementation may produce different results from `zxcvbn`, and estimated search space does not represent actual attacker cost.
- **Wordlist checks:** A match indicates that a candidate appears in the configured local wordlist. A non-match does not prove that the password is strong or uncompromised.
- **Audit coverage:** Results depend on the available input data, operating-system permissions, supported hash formats, installed dependencies, and parser compatibility.
- **Report storage:** Audit history is stored locally in SQLite under the `reports` directory. Report files and database records may contain sensitive account metadata and should be protected.
- **Test coverage:** Automated tests cover selected functionality, including password utilities, wordlist lookup, report redaction, exports, NT hash validation, and audit-history operations. They do not replace live integration testing against actual Linux shadow files or Windows SAM data.



## Limitations and Responsible Use

PassGuard is intended for educational, defensive, and authorized password-auditing activities.

- **Authorization:** Use PassGuard only on systems, accounts, and credential data that you own or are explicitly authorized to audit.
- **Sensitive data:** Passwords, password hashes, SAM/SYSTEM hive files, audit reports, and audit-history databases must be treated as sensitive information.
- **Credential protection:** Do not share or publish plaintext passwords, complete password hashes, exported credential files, or reports containing sensitive account information.
- **Report handling:** Store exported reports securely and review their contents before sharing them. Delete temporary credential files and reports when they are no longer required, in accordance with applicable data-handling policies.
- **Privilege management:** Run PassGuard with only the permissions required for the selected audit. Do not weaken system security settings or change protected file permissions to bypass access controls.
- **Interpretation of results:** A successful audit, a high strength score, or the absence of wordlist matches does not guarantee that a password or system is secure.
- **Verification:** Review important findings and validate them using appropriate security procedures. Unsupported or failed hash checks must not be interpreted as evidence of strong passwords.
- **Legal and ethical use:** The user is responsible for obtaining proper authorization and complying with applicable laws, regulations, and organizational policies.

PassGuard is provided for educational and defensive purposes. The project does not guarantee the detection of every weak password or the prevention of unauthorized access.



## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
